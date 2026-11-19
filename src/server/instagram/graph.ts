
import "server-only";

import { z } from "zod";
import {
  GRAPH_BASE_URL,
} from "./constants";
import { logger } from "@/server/log";

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 2;

export class GraphApiError extends Error {
  status: number;
  code: number | null;
  subcode: number | null;
  type: string | null;
  fbtraceId: string | null;

  constructor(
    message: string,
    options: {
      status: number;
      code?: number | null;
      subcode?: number | null;
      type?: string | null;
      fbtraceId?: string | null;
    },
  ) {
    super(message);

    this.name = "GraphApiError";
    this.status = options.status;
    this.code = options.code ?? null;
    this.subcode = options.subcode ?? null;
    this.type = options.type ?? null;
    this.fbtraceId = options.fbtraceId ?? null;
  }

  get isAuthError(): boolean {
    return (
      this.status === 401 ||
      this.code === 190 ||
      this.code === 102
    );
  }
}

const graphErrorSchema = z.object({
  error: z.object({
    message: z.string().optional(),
    type: z.string().optional(),
    code: z.number().optional(),
    error_subcode: z.number().optional(),
    fbtrace_id: z.string().optional(),
  }),
});

export const graphId = z.union([
  z.string(),
  z.number(),
]).transform(String);

export function safeErrorMessage(error: unknown): string {
  if (error instanceof GraphApiError) {
    return error.message;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "An unexpected Graph API error occurred.";
}

export function isGraphAuthError(error: unknown): boolean {
  return (
    error instanceof GraphApiError &&
    error.isAuthError
  );
}

type GraphRequestOptions = {
  method?: "GET" | "POST" | "DELETE";
  accessToken?: string;
  params?: Record<
    string,
    string | number | boolean | null | undefined
  >;
  body?: Record<
    string,
    string | number | boolean | null | undefined
  >;
  timeoutMs?: number;
  retries?: number;
  retryable?: boolean;
};

function buildUrl(
  path: string,
  params?: GraphRequestOptions["params"],
): URL {
  const url = /^https:\/\//i.test(path)
    ? new URL(path)
    : new URL(
        `${GRAPH_BASE_URL}${
          path.startsWith("/") ? path : `/${path}`
        }`,
      );

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }
  }

  return url;
}

function buildError(
  response: Response,
  payload: unknown,
): GraphApiError {
  const parsed = graphErrorSchema.safeParse(payload);

  if (parsed.success) {
    const error = parsed.data.error;

    return new GraphApiError(
      error.message ?? "Meta Graph API request failed.",
      {
        status: response.status,
        code: error.code,
        subcode: error.error_subcode,
        type: error.type,
        fbtraceId: error.fbtrace_id,
      },
    );
  }

  return new GraphApiError(
    `Meta Graph API request failed (${response.status}).`,
    {
      status: response.status,
    },
  );
}

function shouldRetry(
  error: unknown,
  attempt: number,
  maxRetries: number,
): boolean {
  if (attempt >= maxRetries) {
    return false;
  }

  if (error instanceof GraphApiError) {
    return (
      error.status === 429 ||
      error.status >= 500
    );
  }

  return true;
}

async function wait(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export async function graphRequest<T>(
  path: string,
  options: GraphRequestOptions = {},
): Promise<T> {
  const {
    method = "GET",
    accessToken,
    params,
    body,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = MAX_RETRIES,
    retryable,
  } = options;

  const url = buildUrl(path, {
    ...params,
    ...(accessToken
      ? { access_token: accessToken }
      : {}),
  });

  const canRetry =
    retryable ?? method === "GET";

  const maxRetries = canRetry ? retries : 0;

  let lastError: unknown;

  for (
    let attempt = 0;
    attempt <= maxRetries;
    attempt++
  ) {
    const controller = new AbortController();

    const timeout = setTimeout(
      () => controller.abort(),
      timeoutMs,
    );

    try {
      const headers: Record<string, string> = {
        Accept: "application/json",
      };

      let requestBody: string | undefined;

      if (body) {
        headers["Content-Type"] =
          "application/x-www-form-urlencoded";

        const form = new URLSearchParams();

        for (const [key, value] of Object.entries(body)) {
          if (value !== undefined && value !== null) {
            form.set(key, String(value));
          }
        }

        requestBody = form.toString();
      }

      const response = await fetch(url.toString(), {
        method,
        headers,
        body: requestBody,
        signal: controller.signal,
        cache: "no-store",
      });

      const payload: unknown = await response
        .json()
        .catch(() => null);

      if (!response.ok) {
        throw buildError(response, payload);
      }

      if (
        payload &&
        typeof payload === "object" &&
        "error" in payload
      ) {
        throw buildError(response, payload);
      }

      return payload as T;
    } catch (error) {
      lastError = error;

      if (
        !shouldRetry(error, attempt, maxRetries)
      ) {
        break;
      }

      const delay = Math.min(
        500 * 2 ** attempt,
        4000,
      );

      await wait(delay);
    } finally {
      clearTimeout(timeout);
    }
  }

  logger.error(
    {
      error:
        lastError instanceof Error
          ? lastError.message
          : "Unknown error",
      method,
      path,
    },
    "Meta Graph API request failed",
  );

  if (lastError instanceof GraphApiError) {
    throw lastError;
  }

  if (
    lastError instanceof Error &&
    lastError.name === "AbortError"
  ) {
    throw new Error(
      "Meta Graph API request timed out.",
    );
  }

  throw new Error(
    safeErrorMessage(lastError),
  );
}
