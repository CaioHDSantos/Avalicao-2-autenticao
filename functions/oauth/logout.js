import {
  getCookie, SESSION_COOKIE, clearSessionCookie, NO_STORE,
} from "../_shared/cookies.js";
import { sha256Hex } from "../_shared/crypto.js";

export async function onRequestPost({ request, env }) {
  // Origin precisa ser exatamente PUBLIC_BASE_URL
  if (request.headers.get("Origin") !== env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida.", { status: 403, headers: NO_STORE });
  }

  const raw = getCookie(request, SESSION_COOKIE);
  if (raw) {
    await env.DB
      .prepare("DELETE FROM sessions WHERE id_hash = ?")
      .bind(await sha256Hex(raw))
      .run();
  }

  const headers = new Headers(NO_STORE);
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", clearSessionCookie());
  return new Response(null, { status: 303, headers });
}

// Qualquer outro método é recusado
export function onRequest() {
  return new Response("Método não permitido.", {
    status: 405,
    headers: { ...NO_STORE, Allow: "POST" },
  });
}
