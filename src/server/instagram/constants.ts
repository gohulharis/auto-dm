
import "server-only";

export const GRAPH_API_VERSION = "v25.0";

export const GRAPH_HOST = "https://graph.facebook.com";

export const GRAPH_BASE_URL = `${GRAPH_HOST}/${GRAPH_API_VERSION}`;

/**
 * Meta Unified Login authorization endpoint.
 */
export const IG_AUTHORIZE_URL =
  "https://www.facebook.com/dialog/oauth";

/**
 * Unified Login authorization-code exchange endpoint.
 */
export const IG_TOKEN_URL =
  `${GRAPH_BASE_URL}/oauth/access_token`;

/**
 * Legacy Instagram Login endpoints.
 * Keep these only for existing Instagram Login accounts.
 */
export const IG_SHORT_TOKEN_URL =
  "https://api.instagram.com/oauth/access_token";

export const IG_LONG_TOKEN_URL =
  "https://graph.instagram.com/access_token";

export const IG_REFRESH_TOKEN_URL =
  "https://graph.instagram.com/refresh_access_token";

/**
 * Legacy Instagram Login scopes.
 * Unified Login uses the permissions selected in the Meta configuration.
 */
export const IG_SCOPES = [
  "instagram_business_basic",
  "instagram_business_manage_comments",
  "instagram_business_manage_messages",
] as const;

export const DM_MAX_CHARS = 1000;

export const BUTTON_TEMPLATE_TEXT_MAX = 640;

export const BUTTON_TITLE_MAX = 20;

export const COMMENT_MAX_CHARS = 2200;
