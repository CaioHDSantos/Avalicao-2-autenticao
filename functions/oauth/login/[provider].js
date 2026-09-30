import { getProvider, redirectUri } from "../../_shared/providers.js";
import { randomToken, sha256Hex, sha256Base64Url } from "../../_shared/crypto.js";
import { txCookie, TX_SECONDS, NO_STORE, notFound } from "../../_shared/cookies.js";

export async function onRequestGet({ env, params }) {
  const provider = getProvider(params.provider, env);
  if (!provider) return notFound();

  const txId = randomToken(); // vai no cookie
  const state = randomToken();
  const codeVerifier = randomToken();
  const nonce = provider.usesNonce ? randomToken() : null; // só Google
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const now = Math.floor(Date.now() / 1000);

  // limpeza de transações vencidas
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE expires_at < ?").bind(now).run();

  // Guarda apenas resumos (cookie e state) + verifier + nonce
  await env.DB
    .prepare(
      "INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(
      await sha256Hex(txId),
      provider.name,
      await sha256Hex(state),
      nonce,
      codeVerifier,
      now + TX_SECONDS
    )
    .run();

  const url = new URL(provider.authUrl);
  url.searchParams.set("client_id", provider.clientId);
  url.searchParams.set("redirect_uri", redirectUri(env, provider.name));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (provider.scope) url.searchParams.set("scope", provider.scope);
  if (nonce) url.searchParams.set("nonce", nonce);

  const headers = new Headers(NO_STORE);
  headers.set("Location", url.toString());
  headers.append("Set-Cookie", txCookie(txId));
  return new Response(null, { status: 302, headers });
}
