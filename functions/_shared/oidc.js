// Validação manual do id_token do Google (OIDC), sem bibliotecas.

import { fromBase64Url } from "./crypto.js";

const ISSUER = "https://accounts.google.com";
const decoder = new TextDecoder();
const encoder = new TextEncoder();

const parsePart = (part) => JSON.parse(decoder.decode(fromBase64Url(part)));

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("Falha ao obter documento OIDC");
  return res.json();
}

export async function validateGoogleIdToken(idToken, { clientId, nonce }) {
  // 1. três partes
  if (typeof idToken !== "string") throw new Error("id_token ausente");
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Formato de JWT inválido");

  // 2. cabeçalho com alg RS256
  const header = parsePart(parts[0]);
  if (header.alg !== "RS256") throw new Error("Algoritmo inválido");

  // 3. documento de descoberta do emissor esperado
  const discovery = await getJson(`${ISSUER}/.well-known/openid-configuration`);
  if (discovery.issuer !== ISSUER) throw new Error("Emissor da descoberta inválido");
  if (!String(discovery.jwks_uri).startsWith("https://")) throw new Error("jwks_uri inválido");

  // 4 e 5. JWKS e chave pelo kid
  const jwks = await getJson(discovery.jwks_uri);
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("Chave não encontrada");

  // 6 e 7. importar a chave e verificar a assinatura
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromBase64Url(parts[2]),
    encoder.encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) throw new Error("Assinatura inválida");

  // 8. validar iss, aud, exp, iat e nonce
  const p = parsePart(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;

  if (p.iss !== ISSUER && p.iss !== "accounts.google.com") throw new Error("iss inválido");
  const audiences = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (!audiences.includes(clientId)) throw new Error("aud inválido");
  if (typeof p.exp !== "number" || p.exp <= now - skew) throw new Error("Token expirado");
  if (typeof p.iat !== "number" || p.iat > now + skew) throw new Error("iat inválido");
  if (!nonce || p.nonce !== nonce) throw new Error("nonce inválido");
  if (typeof p.sub !== "string" || !p.sub) throw new Error("sub ausente");

  return {
    issuer: ISSUER,
    subject: p.sub,
    email: p.email ?? null,
    displayName: p.name ?? p.email ?? null,
  };
}
