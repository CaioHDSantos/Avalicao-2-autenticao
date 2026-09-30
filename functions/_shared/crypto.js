// Utilitários de criptografia usando apenas Web Crypto (sem bibliotecas).

const encoder = new TextEncoder();

// bytes -> Base64URL sem preenchimento
export function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Base64URL -> bytes
export function fromBase64Url(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// 32 bytes aleatórios em Base64URL (43 caracteres)
export function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}

// Resumo em hexadecimal (usado para guardar cookies e state no D1)
export async function sha256Hex(text) {
  const bytes = await sha256(text);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Resumo em Base64URL (usado no code_challenge do PKCE)
export async function sha256Base64Url(text) {
  return toBase64Url(await sha256(text));
}
