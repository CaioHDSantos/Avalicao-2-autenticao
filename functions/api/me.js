import { getCookie, SESSION_COOKIE, NO_STORE } from "../_shared/cookies.js";
import { sha256Hex } from "../_shared/crypto.js";

export async function onRequestGet({ request, env }) {
  const unauthorized = () =>
    Response.json({ error: "unauthorized" }, { status: 401, headers: NO_STORE });

  const raw = getCookie(request, SESSION_COOKIE);
  if (!raw) return unauthorized();

  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB
    .prepare(
      "SELECT issuer, email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?"
    )
    .bind(await sha256Hex(raw), now)
    .first();

  if (!row) return unauthorized();

  // Perfil mínimo
  return Response.json(
    { provider: row.issuer, email: row.email, displayName: row.display_name },
    { headers: NO_STORE }
  );
}
