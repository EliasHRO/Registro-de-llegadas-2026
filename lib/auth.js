// Utilidades de autenticación compartidas, basadas en Web Crypto (nativo de Cloudflare Workers).

const TOKEN_SECRET = "vidri-torre-control-nejapa-2026";

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function b64urlEncode(str) {
  return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return decodeURIComponent(escape(atob(str)));
}

export function makeSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

export async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = hexToBytes(saltHex);
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return bytesToHex(new Uint8Array(bits));
}

export async function verifyPassword(password, saltHex, expectedHash) {
  const hash = await hashPassword(password, saltHex);
  if (hash.length !== expectedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(TOKEN_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return bytesToHex(new Uint8Array(sig));
}

export async function signToken(username, role) {
  const payload = JSON.stringify({ u: username, r: role, exp: Date.now() + 12 * 3600 * 1000 });
  const payloadB64 = b64urlEncode(payload);
  const sig = await hmacHex(payloadB64);
  return `${payloadB64}.${sig}`;
}

export async function verifyToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [payloadB64, sig] = token.split(".");
  const expectedSig = await hmacHex(payloadB64);
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(b64urlDecode(payloadB64));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return { username: payload.u, role: payload.r };
  } catch {
    return null;
  }
}

export function getTokenFromRequest(request) {
  const header = request.headers.get("authorization") || "";
  return header.replace(/^Bearer\s+/i, "").trim();
}

export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

export function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS }
  });
}

// Lista TODAS las claves con un prefijo dado (con paginación por si acaso).
export async function kvListByPrefix(kv, prefix) {
  let cursor;
  const names = [];
  do {
    const res = await kv.list({ prefix, cursor });
    names.push(...res.keys.map((k) => k.name));
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  return names;
}
