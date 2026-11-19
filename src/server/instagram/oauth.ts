
import "server-only";

import { createHmac } from "node:crypto";
import { z } from "zod";

import { appUrl } from "@/env";
import {
  deriveKey,
  randomToken,
  safeEqual,
} from "@/server/crypto";
import type { InstagramAccount } from "@/server/db/schema";
import type { SubscriptionStatus } from "@/lib/webhook-diagnostics";
import { logger } from "@/server/log";
import { getSettings, setSetting } from "@/server/settings";

import {
  getActiveAccount,
  tokenResponseSchema,
  upsertAccount,
} from "./account";

import {
  IG_AUTHORIZE_URL,
  IG_TOKEN_URL,
} from "./constants";

import {
  GraphApiError,
  graphId,
  graphRequest,
  safeErrorMessage,
} from "./graph";

const log = logger("oauth");

export const OAUTH_STATE_COOKIE = "ig_oauth_state";
export const OAUTH_STATE_MAX_AGE_S = 10 * 60;
export const OAUTH_CALLBACK_PATH =
  "/api/instagram/oauth/callback";

/** Machine-readable failure reasons surfaced to the settings page. */
export type OAuthErrorCode =
  | "missing_app_credentials"
  | "access_denied"
  | "invalid_state"
  | "missing_code"
  | "missing_permissions"
  | "token_exchange_failed"
  | "profile_fetch_failed";

export class OAuthFlowError extends Error {
  override readonly name = "OAuthFlowError";

  constructor(
    readonly code: OAuthErrorCode,
    readonly cause?: unknown,
  ) {
    super(code);
  }
}

/** The redirect URI registered in the Meta app dashboard. */
export function oauthRedirectUri(): string {
  return `${appUrl()}${OAUTH_CALLBACK_PATH}`;
}

/* ---------------------------------- state ---------------------------------- */

function signState(state: string): string {
  return createHmac("sha256", deriveKey("session"))
    .update(`ig-oauth:${state}`)
    .digest("base64url");
}

/** Creates a CSRF-protected OAuth state. */
export function createOAuthState(): {
  state: string;
  cookieValue: string;
} {
  const state = randomToken(32);

  return {
    state,
    cookieValue: `${state}.${signState(state)}`,
  };
}

/** Verifies the returned state against the signed cookie. */
export function verifyOAuthState(
  returnedState: string | null,
  cookieValue: string | undefined,
): boolean {
  if (!returnedState || !cookieValue) return false;

  const dot = cookieValue.lastIndexOf(".");

  if (dot <= 0) return false;

  const state = cookieValue.slice(0, dot);
  const sig = cookieValue.slice(dot + 1);

  return (
    safeEqual(sig, signState(state)) &&
    safeEqual(state, returnedState)
  );
}

/* ---------------------------------- config --------------------------------- */

async function getAppCredentials(): Promise<{
  appId: string;
  appSecret: string;
  configId: string;
}> {
  const settings = await getSettings([
    "meta.appId",
    "meta.appSecret",
    "meta.configId",
  ]);

  const appId = settings["meta.appId"];
  const appSecret = settings["meta.appSecret"];
  const configId = settings["meta.configId"];

  if (!appId || !appSecret || !configId) {
    throw new OAuthFlowError(
      "missing_app_credentials",
    );
  }

  return {
    appId,
    appSecret,
    configId,
  };
}

/* ----------------------------- authorization ------------------------------ */

/** Builds the Meta Unified Login authorization URL. */
export async function buildAuthorizeUrl(
  state: string,
): Promise<string> {
  const { appId, configId } =
    await getAppCredentials();

  const url = new URL(IG_AUTHORIZE_URL);

  url.searchParams.set("client_id", appId);
  url.searchParams.set("config_id", configId);
  url.searchParams.set("display", "popup");
  url.searchParams.set(
    "override_default_response_type",
    "true",
  );
  url.searchParams.set(
    "redirect_uri",
    oauthRedirectUri(),
  );
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "login");

  return url.toString();
}

/* ------------------------------- API schemas ------------------------------- */

const profileSchema = z.object({
  id: graphId,
  username: z.string().min(1),
  name: z.string().nullish(),
  profile_picture_url: z.string().nullish(),
});

const assignedInstagramAccountsSchema = z.object({
  data: z.array(profileSchema),
});

const subscribeSchema = z.object({
  success: z.boolean().optional(),
});

const subscribedAppsSchema = z.object({
  data: z
    .array(
      z.object({
        subscribed_fields: z.array(z.string()).optional(),
      }).passthrough(),
    )
    .optional(),
});

export interface ConnectResult {
  account: InstagramAccount;
  /** False when the account was saved but webhook subscription failed. */
  subscribed: boolean;
}

/* ------------------------------ token exchange ----------------------------- */

/**
 * Exchanges the authorization code for a Unified Login system-user token.
 *
 * Unified Login does not use the old Instagram Login
 * short-lived-to-long-lived token exchange.
 */
async function exchangeAuthorizationCode(
  code: string,
  appId: string,
  appSecret: string,
): Promise<z.infer<typeof tokenResponseSchema>> {
  const result = await graphRequest<unknown>(
    IG_TOKEN_URL,
    {
      method: "GET",
      params: {
        client_id: appId,
        client_secret: appSecret,
        redirect_uri: oauthRedirectUri(),
        code,
      },
      retries: 0,
      timeoutMs: 15_000,
    },
  );

  return tokenResponseSchema.parse(result);
}

/* ---------------------------- account discovery ---------------------------- */

/**
 * Finds Instagram professional accounts assigned to the system user.
 *
 * This application currently supports one active Instagram account.
 */
async function fetchAssignedInstagramAccount(
  accessToken: string,
): Promise<z.infer<typeof profileSchema>> {
  const result = await graphRequest<unknown>(
    "/me/assigned_instagram_accounts",
    {
      params: {
        fields:
          "id,username,name,profile_picture_url",
      },
      accessToken,
      retries: 0,
    },
  );

  const parsed =
    assignedInstagramAccountsSchema.parse(result);

  if (parsed.data.length !== 1) {
    throw new OAuthFlowError(
      "profile_fetch_failed",
      new Error(
        `Expected exactly one assigned Instagram account; received ${parsed.data.length}`,
      ),
    );
  }

  return parsed.data[0]!;
}

/* ---------------------------------- connect -------------------------------- */

/**
 * Completes Unified Login:
 *
 * authorization code
 *   -> system-user access token
 *   -> assigned Instagram account
 *   -> encrypted database storage
 *   -> Instagram webhook subscription
 */
export async function completeOAuth(
  rawCode: string,
): Promise<ConnectResult> {
  const { appId, appSecret } =
    await getAppCredentials();

  // Meta may append #_ to the authorization code.
  const code = rawCode.replace(/#_$/, "");

  if (!code) {
    throw new OAuthFlowError("missing_code");
  }

  let token: z.infer<typeof tokenResponseSchema>;

  try {
    token = await exchangeAuthorizationCode(
      code,
      appId,
      appSecret,
    );
  } catch (err) {
    log.warn("oauth.token_exchange_failed", {
      error: safeErrorMessage(err),
    });

    throw new OAuthFlowError(
      "token_exchange_failed",
      err,
    );
  }

  let profile: z.infer<typeof profileSchema>;

  try {
    profile = await fetchAssignedInstagramAccount(
      token.access_token,
    );
  } catch (err) {
    log.warn("oauth.account_lookup_failed", {
      error: safeErrorMessage(err),
    });

    if (err instanceof OAuthFlowError) {
      throw err;
    }

    throw new OAuthFlowError(
      "profile_fetch_failed",
      err,
    );
  }

  const account = await upsertAccount({
    igUserId: profile.id,
    username: profile.username,
    name: profile.name ?? null,
    profilePictureUrl:
      profile.profile_picture_url ?? null,
    accessToken: token.access_token,
    expiresInSeconds: token.expires_in ?? null,
    tokenType: "unified_login",
  });

  const status = await subscribeAndRecord(
    token.access_token,
    "connect",
    account.igUserId,
  );

  return {
    account,
    subscribed: status.ok,
  };
}

/* ------------------------------ webhooks ----------------------------------- */

/** Webhook fields required by the application. */
export const WEBHOOK_SUBSCRIBED_FIELDS =
  "comments,messaging_postbacks";

/**
 * Resolves the Instagram account ID.
 * The optional argument keeps existing callers compatible.
 */
async function resolveInstagramUserId(
  igUserId?: string,
): Promise<string> {
  if (igUserId) return igUserId;

  const account = await getActiveAccount();

  if (!account) {
    throw new Error("No Instagram account connected");
  }

  return account.igUserId;
}

/**
 * Subscribes the Instagram professional account to webhook fields.
 */
export async function subscribeWithDetails(
  accessToken: string,
  igUserId?: string,
): Promise<{
  ok: boolean;
  fields?: string[];
  error?: string;
}> {
  try {
    const accountId =
      await resolveInstagramUserId(igUserId);

    const result = await graphRequest<unknown>(
      `/${accountId}/subscribed_apps`,
      {
        method: "POST",
        params: {
          subscribed_fields:
            WEBHOOK_SUBSCRIBED_FIELDS,
        },
        accessToken,
        retries: 0,
      },
    );

    const parsed = subscribeSchema.parse(result);

    if (parsed.success === false) {
      return {
        ok: false,
        error: "Instagram answered success: false",
      };
    }

    try {
      const current = await graphRequest<unknown>(
        `/${accountId}/subscribed_apps`,
        {
          accessToken,
          retries: 0,
          timeoutMs: 5_000,
        },
      );

      const parsedCurrent =
        subscribedAppsSchema.parse(current);

      const fields = [
        ...new Set(
          (parsedCurrent.data ?? []).flatMap(
            (item) => item.subscribed_fields ?? [],
          ),
        ),
      ].slice(0, 20);

      return {
        ok: true,
        fields,
      };
    } catch {
      // Subscription succeeded; verification was unavailable.
      return { ok: true };
    }
  } catch (err) {
    if (err instanceof GraphApiError) {
      return {
        ok: false,
        error: safeErrorMessage(err),
      };
    }

    log.warn("webhook.subscription_failed", {
      error: safeErrorMessage(err),
    });

    return {
      ok: false,
      error: safeErrorMessage(err),
    };
  }
}

/** Subscribes the currently connected Instagram account. */
export async function subscribeToWebhooks(
  accessToken: string,
  igUserId?: string,
): Promise<boolean> {
  const result = await subscribeWithDetails(
    accessToken,
    igUserId,
  );

  return result.ok;
}

/** Subscribes and records the result in the webhook settings. */
export async function subscribeAndRecord(
  accessToken: string,
  source: SubscriptionStatus["source"],
  igUserId?: string,
): Promise<SubscriptionStatus> {
  const result = await subscribeWithDetails(
    accessToken,
    igUserId,
  );

  const status: SubscriptionStatus = {
    ok: result.ok,
    at: new Date().toISOString(),
    source,
    ...(result.fields
      ? { fields: result.fields }
      : {}),
    ...(result.error
      ? { error: result.error }
      : {}),
  };

  try {
    await setSetting(
      "webhook.subscription",
      status,
    );
  } catch (err) {
    log.warn(
      "webhook.subscription_record_failed",
      {
        error: safeErrorMessage(err),
      },
    );
  }

  log.info("webhook.subscribed", {
    ok: status.ok,
    source,
    fields: status.fields,
  });

  return status;
}
