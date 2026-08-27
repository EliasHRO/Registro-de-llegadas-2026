import {
  hashPassword, verifyPassword, makeSalt, signToken, verifyToken,
  getTokenFromRequest, getCountryFromRequest, getFacilityFromRequest,
  VALID_COUNTRIES, COUNTRY_FACILITIES, storageScope, kvListByPrefix, CORS_HEADERS, json,
  allScopes, scopeFromRecordId, scopeLabel
} from "../lib/auth.js";

const EL_SALVADOR_OFFSET_MS = -6 * 60 * 60 * 1000;
const EDITABLE_FIELDS = ["provider", "driverName", "plate", "phone", "transportType", "orderNumber", "customFields", "dock"];

// Superusuarios globales: mismo usuario/contraseña sin importar el país/bodega, con acceso a todos los países.
const SUPERUSER_USERNAMES = ["elias", "carlos"];
const GLOBAL_SCOPE = "GLOBAL";

const ROLE_PERMS = {
  superadmin: { changeStatus: true, editFields: true, delete: true, deleteLinked: true, manage: true },
  admin:      { changeStatus: true, editFields: true, delete: true, deleteLinked: false, manage: true },
  operador:   { changeStatus: true, editFields: true, delete: false, deleteLinked: false, manage: false },
  asistente:  { changeStatus: true, editFields: false, delete: false, deleteLinked: false, manage: false },
  viewer:     { changeStatus: false, editFields: false, delete: false, deleteLinked: false, manage: false },
  conductor:  { changeStatus: false, editFields: false, delete: false, deleteLinked: false, manage: false }
};
function permsFor(role) { return ROLE_PERMS[role] || ROLE_PERMS.viewer; }
function isAdminRole(role) { return role === "admin" || role === "superadmin"; }
// Verifica un token de PERSONAL INTERNO. A diferencia de verifyToken (genérico), esto rechaza
// explícitamente los tokens de proveedor (role:"provider") — su identidad es completamente aparte
// y nunca debe poder leer datos de ningún endpoint del panel administrativo.
async function verifyStaffToken(request) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role === "provider") return null;
  return auth;
}

// Devuelve el registro del usuario autenticado (global si es el superusuario, o del scope si es normal).
// Se usa para reverificar la contraseña en acciones sensibles (eliminar campos, purgar la papelera).
async function getUserRecord(kv, auth) {
  if (auth.global) return kv.get(`${GLOBAL_SCOPE}:user:${auth.username}`, "json");
  return kv.get(`${storageScope(auth.country, auth.facility)}:user:${auth.username}`, "json");
}

function haversineMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// Resuelve país + bodega desde los encabezados de una solicitud pública (sin token).
// Devuelve null si el país es inválido, o si el país requiere bodega y no vino una válida.
function resolvePublicScope(request) {
  const country = getCountryFromRequest(request);
  if (!country) return null;
  if (COUNTRY_FACILITIES[country]) {
    const facility = getFacilityFromRequest(request, country);
    if (!facility) return null;
    return storageScope(country, facility);
  }
  return storageScope(country, null);
}

// Resuelve en qué país/bodega debe operar una escritura (crear/editar/eliminar campos, muelles, settings, usuarios).
// Usuarios normales: siempre su propio scope (fijado al iniciar sesión).
// Superusuario: usa el país/bodega "activo" que eligió en el selector dentro del panel (enviado en X-Country/X-Facility),
// o el data.scope explícito si la acción ya lo trae (por ejemplo al editar un usuario de otro país en la lista global).
function resolveWriteScope(request, auth, data) {
  if (auth.global) {
    if (data && data.scope) return allScopes().includes(data.scope) ? data.scope : null;
    return resolvePublicScope(request);
  }
  if (Array.isArray(auth.multiScopes) && auth.multiScopes.length) {
    // Admin con acceso a varios países/bodegas (asignado por el superusuario): puede operar en cualquiera de sus scopes asignados.
    if (data && data.scope) return auth.multiScopes.includes(data.scope) ? data.scope : null;
    const headerScope = resolvePublicScope(request);
    if (headerScope && auth.multiScopes.includes(headerScope)) return headerScope;
    return storageScope(auth.country, auth.facility);
  }
  return storageScope(auth.country, auth.facility);
}

// Valida que un scope (país o país:bodega) esté permitido para este usuario (global, multiScopes, o su propio scope).
function scopeAllowedForAuth(auth, scope) {
  if (!scope) return false;
  if (auth.global) return allScopes().includes(scope);
  if (Array.isArray(auth.multiScopes) && auth.multiScopes.length) return auth.multiScopes.includes(scope);
  return scope === storageScope(auth.country, auth.facility);
}

// Igual que scopeAllowedForAuth, pero además permite escribir en cualquier bodega del MISMO país cuando
// ese país tiene varias bodegas (ej. Guatemala: Atlas - Materiales, Atlas - Misceláneo y CD Santa Elena) — porque en Programación de
// Citas cualquier admin de ese país ya puede VER las citas de todas sus bodegas (ver handleProvSchedCitas
// GET), así que también debe poder editarlas/cancelarlas/marcarlas, no solo consultarlas.
function citaScopeAllowedForAuth(auth, scope) {
  if (scopeAllowedForAuth(auth, scope)) return true;
  if (!scope || auth.global || (Array.isArray(auth.multiScopes) && auth.multiScopes.length)) return false;
  if (COUNTRY_FACILITIES[auth.country] && COUNTRY_FACILITIES[auth.country].length) {
    return scope.startsWith(`${auth.country}:`);
  }
  return false;
}

// ---------------- /api/auth ----------------
async function handleAuth(request, env) {
  if (request.method !== "POST") return json({ error: "Método no permitido" }, 405);
  const data = await readJson(request);
  if (!data) return json({ error: "JSON inválido" }, 400);
  const username = (data.username || "").trim().toLowerCase();
  const password = data.password || "";
  if (!username || !password) return json({ error: "Usuario y contraseña son obligatorios" }, 400);

  const kv = env.TORRE_KV;

  // ---- Superusuarios globales: entran directo con usuario/contraseña, sin elegir país ni bodega.
  // Tienen acceso y permisos de eliminar sobre TODOS los países y bodegas. Cada uno tiene su propia contraseña. ----
  if (SUPERUSER_USERNAMES.includes(username)) {
    let superUser = await kv.get(`${GLOBAL_SCOPE}:user:${username}`, "json");
    if (!superUser) {
      const salt = makeSalt();
      superUser = {
        username,
        passwordHash: await hashPassword("Torre2026", salt),
        salt, role: "superadmin", isOwner: true, createdAt: Date.now()
      };
      await kv.put(`${GLOBAL_SCOPE}:user:${username}`, JSON.stringify(superUser));
    }
    const ok = await verifyPassword(password, superUser.salt, superUser.passwordHash);
    if (!ok) return json({ error: "Usuario o contraseña incorrectos" }, 401);
    const token = await signToken(superUser.username, "superadmin", null, null, true, true);
    return json({ token, username: superUser.username, role: "superadmin", country: null, facility: null, isOwner: true, global: true });
  }

  // ---- Usuarios normales: siguen atados a un país/bodega elegido en el login. ----
  const country = getCountryFromRequest(request);
  if (!country) return json({ error: "País inválido o no especificado" }, 400);
  let facility = null;
  if (COUNTRY_FACILITIES[country]) {
    facility = getFacilityFromRequest(request, country);
    if (!facility) return json({ error: "Selecciona una bodega válida" }, 400);
  }

  const scope = storageScope(country, facility);
  const userKeys = await kvListByPrefix(kv, `${scope}:user:`);
  let hasAdmin = false;
  for (const key of userKeys) {
    const u = await kv.get(key, "json");
    if (u && u.role === "admin") { hasAdmin = true; break; }
  }
  if (!hasAdmin) {
    const salt = makeSalt();
    await kv.put(`${scope}:user:admin`, JSON.stringify({
      username: "admin",
      passwordHash: await hashPassword("Torre2026", salt),
      salt, role: "admin", isOwner: true, createdAt: Date.now()
    }));
  }

  const user = await kv.get(`${scope}:user:${username}`, "json");
  if (!user) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  // Compatibilidad: cuentas "admin" creadas antes de que existiera isOwner se tratan como propietarias.
  const isOwner = user.isOwner === true || (user.isOwner === undefined && user.username === "admin");

  // El país/bodega con el que el usuario inicia sesión SIEMPRE forma parte de sus scopes permitidos,
  // aunque el superusuario no lo haya marcado explícitamente al asignarle países/bodegas adicionales.
  const homeScope = storageScope(country, facility);
  const effectiveMultiScopes = Array.isArray(user.multiScopes) && user.multiScopes.length
    ? Array.from(new Set([homeScope, ...user.multiScopes]))
    : null;

  const token = await signToken(user.username, user.role, country, facility, isOwner, false, Array.isArray(user.allowedViews) ? user.allowedViews : null, effectiveMultiScopes);
  return json({ token, username: user.username, role: user.role, country, facility, isOwner, global: false, allowedViews: Array.isArray(user.allowedViews) ? user.allowedViews : null, multiScopes: effectiveMultiScopes });
}

const NAV_VIEW_KEYS = ["dashboard", "calendar", "provsched", "provsched-view", "insights-arrivals", "suggest", "config"];
function sanitizeAllowedViews(input) {
  if (!Array.isArray(input)) return null;
  const clean = input.filter((v) => NAV_VIEW_KEYS.includes(v));
  if (clean.length === 0 || clean.length === NAV_VIEW_KEYS.length) return null; // vacío o todo marcado = sin restricción
  return clean;
}
function sanitizeMultiScopes(input) {
  if (!Array.isArray(input)) return null;
  const clean = input.filter((s) => allScopes().includes(s));
  if (clean.length === 0) return null;
  return clean;
}

// ---------------- /api/users ----------------
async function handleUsers(request, env) {
  const auth = await verifyStaffToken(request);
  if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
  const kv = env.TORRE_KV;

  if (request.method === "GET") {
    if (auth.global) {
      // Superusuario: junta los usuarios de TODOS los países y bodegas.
      const users = [];
      for (const s of allScopes()) {
        const keys = await kvListByPrefix(kv, `${s}:user:`);
        for (const key of keys) {
          const u = await kv.get(key, "json");
          if (u) users.push({ username: u.username, role: u.role, createdAt: u.createdAt, scopeKey: s, scopeLabel: scopeLabel(s), allowedViews: Array.isArray(u.allowedViews) ? u.allowedViews : null, multiScopes: Array.isArray(u.multiScopes) ? u.multiScopes : null });
        }
      }
      users.sort((a, b) => a.scopeLabel.localeCompare(b.scopeLabel) || a.username.localeCompare(b.username));
      return json(users);
    }
    const scope = storageScope(auth.country, auth.facility);
    const keys = await kvListByPrefix(kv, `${scope}:user:`);
    const users = [];
    for (const key of keys) {
      const u = await kv.get(key, "json");
      if (u) users.push({ username: u.username, role: u.role, createdAt: u.createdAt, allowedViews: Array.isArray(u.allowedViews) ? u.allowedViews : null, multiScopes: Array.isArray(u.multiScopes) ? u.multiScopes : null });
    }
    users.sort((a, b) => a.username.localeCompare(b.username));
    return json(users);
  }

  if (request.method === "POST") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const targetScope = resolveWriteScope(request, auth, data);
    if (!targetScope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const username = (data.username || "").trim().toLowerCase();
    const password = data.password || "";
    const validRoles = ["admin", "operador", "asistente", "viewer", "conductor"];
    const role = validRoles.includes(data.role) ? data.role : "viewer";
    if (SUPERUSER_USERNAMES.includes(username)) return json({ error: "Ese nombre de usuario está reservado" }, 400);
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
      return json({ error: "El usuario debe tener 3-30 caracteres (letras, números, puntos o guiones)" }, 400);
    }
    if (password.length < 4) return json({ error: "La contraseña debe tener al menos 4 caracteres" }, 400);
    const existing = await kv.get(`${targetScope}:user:${username}`, "json");
    if (existing) return json({ error: `El usuario "${username}" ya existe. Elimínalo primero si quieres reemplazarlo.` }, 400);
    const salt = makeSalt();
    // Qué secciones puede ver este usuario y a qué países/bodegas tiene acceso extra: solo el superusuario global puede definirlo al crear la cuenta.
    const allowedViews = auth.global ? sanitizeAllowedViews(data.allowedViews) : null;
    const multiScopes = auth.global ? sanitizeMultiScopes(data.multiScopes) : null;
    await kv.put(`${targetScope}:user:${username}`, JSON.stringify({
      username, passwordHash: await hashPassword(password, salt), salt, role, isOwner: false, createdAt: Date.now(), allowedViews, multiScopes
    }));
    return json({ ok: true });
  }

  if (request.method === "PATCH") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const targetScope = resolveWriteScope(request, auth, data);
    if (!targetScope) return json({ error: "País/bodega inválido" }, 400);
    const oldUsername = (data.username || "").trim().toLowerCase();
    const existing = await kv.get(`${targetScope}:user:${oldUsername}`, "json");
    if (!existing) return json({ error: "Usuario no encontrado" }, 404);

    if (data.newPassword) {
      if (data.newPassword.length < 4) return json({ error: "La contraseña debe tener al menos 4 caracteres" }, 400);
      const salt = makeSalt();
      existing.passwordHash = await hashPassword(data.newPassword, salt);
      existing.salt = salt;
    }

    if (data.role) {
      const validRoles = ["admin", "operador", "asistente", "viewer", "conductor"];
      if (!validRoles.includes(data.role)) return json({ error: "Rol inválido" }, 400);
      existing.role = data.role;
    }

    // Qué secciones puede ver este usuario y a qué países/bodegas tiene acceso extra: solo el superusuario global puede modificarlo.
    if (auth.global && data.allowedViews !== undefined) {
      existing.allowedViews = sanitizeAllowedViews(data.allowedViews);
    }
    if (auth.global && data.multiScopes !== undefined) {
      existing.multiScopes = sanitizeMultiScopes(data.multiScopes);
    }

    let newUsername = oldUsername;
    if (data.newUsername) {
      newUsername = data.newUsername.trim().toLowerCase();
      if (SUPERUSER_USERNAMES.includes(newUsername)) return json({ error: "Ese nombre de usuario está reservado" }, 400);
      if (!/^[a-z0-9._-]{3,30}$/.test(newUsername)) {
        return json({ error: "El usuario debe tener 3-30 caracteres (letras, números, puntos o guiones)" }, 400);
      }
    }

    if (newUsername !== oldUsername) {
      const clash = await kv.get(`${targetScope}:user:${newUsername}`, "json");
      if (clash) return json({ error: `El usuario "${newUsername}" ya existe.` }, 400);
      existing.username = newUsername;
      await kv.put(`${targetScope}:user:${newUsername}`, JSON.stringify(existing));
      await kv.delete(`${targetScope}:user:${oldUsername}`);
    } else {
      await kv.put(`${targetScope}:user:${oldUsername}`, JSON.stringify(existing));
    }
    return json({ ok: true, username: newUsername });
  }

  if (request.method === "DELETE") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const targetScope = resolveWriteScope(request, auth, data);
    if (!targetScope) return json({ error: "País/bodega inválido" }, 400);
    const username = (data.username || "").trim().toLowerCase();
    if (username === auth.username) return json({ error: "No puedes eliminar tu propio usuario" }, 400);
    await kv.delete(`${targetScope}:user:${username}`);
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/formfields ----------------
async function handleFormfields(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const scope = resolvePublicScope(request);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const fields = await kv.get(`${scope}:formfields:custom`, "json");
    return json(fields || []);
  }
  if (request.method === "POST") {
    // Agrega o edita campos. Nunca elimina — para eso está el DELETE, protegido aparte.
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !Array.isArray(data.fields)) return json({ error: "Formato inválido" }, 400);
    const scope = resolveWriteScope(request, auth, data);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const existing = (await kv.get(`${scope}:formfields:custom`, "json")) || [];
    const byId = new Map(existing.map((f) => [f.id, f]));
    for (const f of data.fields) {
      const clean = {
        id: (f.id || "").trim(),
        label: (f.label || "").trim(),
        type: f.type || "text",
        required: !!f.required,
        visible: f.visible !== false,
        options: Array.isArray(f.options) ? f.options.map((o) => (o || "").toString().trim()).filter(Boolean) : undefined
      };
      if (!clean.id || !clean.label) continue;
      byId.set(clean.id, clean);
    }
    const merged = Array.from(byId.values());
    await kv.put(`${scope}:formfields:custom`, JSON.stringify(merged));
    return json({ ok: true, fields: merged });
  }
  if (request.method === "DELETE") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    if (!auth.isOwner) return json({ error: "Solo el usuario propietario puede eliminar campos" }, 403);
    const data = await readJson(request);
    if (!data || !data.fieldId || !data.password) return json({ error: "Falta el campo a eliminar o la contraseña" }, 400);
    const scope = resolveWriteScope(request, auth, data);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);

    const userRec = await getUserRecord(kv, auth);
    if (!userRec) return json({ error: "Usuario no encontrado" }, 404);
    const ok = await verifyPassword(data.password, userRec.salt, userRec.passwordHash);
    if (!ok) return json({ error: "Contraseña incorrecta" }, 401);

    const existing = (await kv.get(`${scope}:formfields:custom`, "json")) || [];
    const filtered = existing.filter((f) => f.id !== data.fieldId);
    await kv.put(`${scope}:formfields:custom`, JSON.stringify(filtered));
    return json({ ok: true, fields: filtered });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/provsched-formfields (campos adicionales del formulario "Nueva programación de proveedor") ----------------
async function handleProvSchedFormfields(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const scope = resolvePublicScope(request);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const fields = await kv.get(`${scope}:provschedfields:custom`, "json");
    return json(fields || []);
  }
  if (request.method === "POST") {
    // Agrega o edita campos. Nunca elimina — para eso está el DELETE, protegido aparte.
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !Array.isArray(data.fields)) return json({ error: "Formato inválido" }, 400);
    const scope = resolveWriteScope(request, auth, data);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const existing = (await kv.get(`${scope}:provschedfields:custom`, "json")) || [];
    const byId = new Map(existing.map((f) => [f.id, f]));
    for (const f of data.fields) {
      const clean = {
        id: (f.id || "").trim(),
        label: (f.label || "").trim(),
        type: f.type || "text",
        required: !!f.required,
        options: Array.isArray(f.options) ? f.options.map((o) => (o || "").toString().trim()).filter(Boolean) : undefined
      };
      if (!clean.id || !clean.label) continue;
      byId.set(clean.id, clean);
    }
    const merged = Array.from(byId.values());
    await kv.put(`${scope}:provschedfields:custom`, JSON.stringify(merged));
    return json({ ok: true, fields: merged });
  }
  if (request.method === "DELETE") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    if (!auth.isOwner) return json({ error: "Solo el usuario propietario puede eliminar campos" }, 403);
    const data = await readJson(request);
    if (!data || !data.fieldId || !data.password) return json({ error: "Falta el campo a eliminar o la contraseña" }, 400);
    const scope = resolveWriteScope(request, auth, data);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);

    const userRec = await getUserRecord(kv, auth);
    if (!userRec) return json({ error: "Usuario no encontrado" }, 404);
    const ok = await verifyPassword(data.password, userRec.salt, userRec.passwordHash);
    if (!ok) return json({ error: "Contraseña incorrecta" }, 401);

    const existing = (await kv.get(`${scope}:provschedfields:custom`, "json")) || [];
    const filtered = existing.filter((f) => f.id !== data.fieldId);
    await kv.put(`${scope}:provschedfields:custom`, JSON.stringify(filtered));
    return json({ ok: true, fields: filtered });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/suggestions ----------------
async function handleSuggestions(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "POST") {
    const auth = await verifyStaffToken(request);
    if (!auth) return json({ error: "No autorizado" }, 403);
    const scope = storageScope(auth.country, auth.facility);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const message = (data.message || "").trim();
    if (!message) return json({ error: "Escribe tu sugerencia" }, 400);
    const id = `${scope}:suggestion:${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = { id, message, from: auth.username, ts: Date.now() };
    await kv.put(id, JSON.stringify(record));
    const settings = await kv.get(`${scope}:settings:config`, "json");
    if (settings && settings.webhookUrl) {
      try {
        await fetch(settings.webhookUrl, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "sugerencia", ...record, notifyEmail: settings.suggestionsEmail || settings.notifyEmail || "" })
        });
      } catch {}
    }
    return json({ ok: true });
  }
  if (request.method === "GET") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const scope = storageScope(auth.country, auth.facility);
    const keys = await kvListByPrefix(kv, `${scope}:suggestion:`);
    const items = [];
    for (const key of keys) { const v = await kv.get(key, "json"); if (v) items.push(v); }
    items.sort((a, b) => b.ts - a.ts);
    return json(items);
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/arrivals ----------------
// Traduce el estado de un registro de llegada al estado que debe reflejar la cita programada vinculada.
function citaStatusFromArrivalStatus(arrivalStatus) {
  if (arrivalStatus === "esperando") return "en_espera";
  if (arrivalStatus === "en_descarga") return "en_descarga";
  if (arrivalStatus === "despachado") return "completado";
  return null;
}

// Una cita "cancelado" o "no_presento" no bloquea el horario ni la orden de compra para citas nuevas —
// en ambos casos, esa orden ya no representa un camión que realmente vaya a llegar.
function isActiveCitaStatus(status) {
  return status !== "cancelado" && status !== "no_presento";
}

// Compara la hora real de check-in del transportista contra la hora que tenía programada la cita,
// y devuelve si llegó a tiempo o tarde (y con cuántos minutos de diferencia).
function computePunctuality(citaDate, citaTime, arrivalDate, arrivalTime) {
  if (!citaDate || !citaTime || !arrivalDate || !arrivalTime) return null;
  const toMinutes = (date, time) => {
    const [y, m, d] = date.split("-").map(Number);
    const [h, mi] = time.split(":").map(Number);
    return Date.UTC(y, m - 1, d, h, mi) / 60000; // minutos absolutos desde época, comparables entre fechas distintas
  };
  const scheduled = toMinutes(citaDate, citaTime);
  const actual = toMinutes(arrivalDate, arrivalTime);
  const diffMinutes = Math.round(actual - scheduled);
  return { status: diffMinutes > 0 ? "tarde" : "a_tiempo", diffMinutes };
}

// ---------------- /api/arrival-status (sin login: para la pantalla de confirmación del transportista) ----------------
// Devuelve solo lo mínimo indispensable (estado, muelle, hora) de UN registro específico, dado su id completo
// (que solo conoce el transportista porque se lo dio el sistema al hacer check-in). Nunca expone otros registros.
async function handleArrivalStatus(request, env) {
  if (request.method !== "GET") return json({ error: "Método no permitido" }, 405);
  const url = new URL(request.url);
  const id = url.searchParams.get("id") || "";
  if (!id || !scopeFromRecordId(id) || !id.includes(":arrival:")) {
    return json({ error: "Id inválido" }, 400);
  }
  const kv = env.TORRE_KV;
  const record = await kv.get(id, "json");
  if (!record) return json({ error: "No encontrado" }, 404);
  return json({
    status: record.status || "esperando",
    dock: record.dock || null,
    time: record.time || null
  });
}

async function handleArrivals(request, env) {
  const kv = env.TORRE_KV;

  if (request.method === "GET") {
    const auth = await verifyStaffToken(request);
    if (!auth) return json({ error: "No autorizado" }, 403);
    const records = [];
    if (auth.global) {
      // Superusuario: junta los registros de TODOS los países y bodegas.
      for (const s of allScopes()) {
        const keys = await kvListByPrefix(kv, `${s}:arrival:`);
        for (const key of keys) {
          const val = await kv.get(key, "json");
          if (val) records.push({ ...val, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else if (Array.isArray(auth.multiScopes) && auth.multiScopes.length) {
      // Admin con acceso a varias bodegas (asignado por el superusuario): junta los registros de todas ellas.
      for (const s of auth.multiScopes) {
        const keys = await kvListByPrefix(kv, `${s}:arrival:`);
        for (const key of keys) {
          const val = await kv.get(key, "json");
          if (val) records.push({ ...val, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else {
      const scope = storageScope(auth.country, auth.facility);
      const keys = await kvListByPrefix(kv, `${scope}:arrival:`);
      for (const key of keys) { const val = await kv.get(key, "json"); if (val) records.push(val); }
    }
    records.sort((a, b) => a.ts - b.ts);
    return json(records);
  }

  if (request.method === "POST") {
    const scope = resolvePublicScope(request);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const provider = (data.provider || "").trim();
    const driverName = (data.driverName || "").trim();
    const plate = (data.plate || "").trim();
    const phone = (data.phone || "").trim();
    const transportType = (data.transportType || "").trim();
    const orderNumber = (data.orderNumber || "").trim().slice(0, 100);
    const customFields = typeof data.customFields === "object" && data.customFields !== null ? data.customFields : {};

    const settings = await kv.get(`${scope}:settings:config`, "json");
    const defaultRequired = { provider: true, driverName: true, phone: true, plate: true, transportType: true };
    const fieldRequired = Object.assign({}, defaultRequired, (settings && settings.fieldRequired) || {});
    const defaultLabels = { provider: "Proveedor", driverName: "Motorista", phone: "Teléfono", plate: "Placa", transportType: "Tipo de transporte" };
    const fieldLabels = Object.assign({}, defaultLabels, (settings && settings.fieldLabels) || {});

    const values = { provider, driverName, plate, phone, transportType };
    const missing = Object.keys(defaultRequired).filter((k) => fieldRequired[k] && !values[k]);
    if (missing.length > 0) {
      return json({ error: `Faltan datos: ${missing.map((k) => fieldLabels[k]).join(", ")}` }, 400);
    }

    const validTypes = (settings && Array.isArray(settings.transportCategories) && settings.transportCategories.length)
      ? settings.transportCategories
      : ["Contenedor", "Camión", "Otros"];
    if (transportType && !validTypes.includes(transportType)) return json({ error: "Tipo de transporte inválido" }, 400);

    let geoDistance = typeof data.geoDistance === "number" ? data.geoDistance : null;
    if (settings && settings.geofenceEnabled && settings.geofenceLat != null && settings.geofenceLng != null) {
      if (typeof data.geoLat !== "number" || typeof data.geoLng !== "number") {
        return json({ error: "Se requiere verificar tu ubicación para registrarte" }, 403);
      }
      const dist = haversineMeters(data.geoLat, data.geoLng, settings.geofenceLat, settings.geofenceLng);
      geoDistance = Math.round(dist);
      if (dist > settings.geofenceRadius) {
        return json({ error: `Estás a ${Math.round(dist)} m del centro. Debes estar a menos de ${settings.geofenceRadius} m.` }, 403);
      }
    }

    const utcNow = new Date();
    const local = new Date(utcNow.getTime() + EL_SALVADOR_OFFSET_MS);
    const date = local.toISOString().slice(0, 10);
    const time = local.toISOString().slice(11, 16);

    // Busca si esta orden de compra coincide con una cita programada (llave principal) — antes de crear
    // el registro, para poder aplicar el umbral de "entrada anticipada" si está configurado.
    let matchedCitaKey = null, matchedCita = null;
    if (orderNumber) {
      const citaKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
      for (const key of citaKeys) {
        const cita = await kv.get(key, "json");
        if (
          cita && cita.status !== "cancelado" && !cita.linkedArrivalId &&
          (cita.orderNumber || "").trim().toLowerCase() === orderNumber.toLowerCase()
        ) {
          matchedCitaKey = key;
          matchedCita = cita;
          break;
        }
      }
    }

    // Umbral de entrada anticipada: si está configurado, el check-in de una cita programada solo se
    // acepta desde ese número de minutos antes de la hora programada — no más temprano.
    if (matchedCita) {
      const provConfig = (await kv.get(`${scope}:provsched:config`, "json")) || PROVSCHED_DEFAULT_CONFIG;
      const earlyLimit = provConfig.earlyCheckinMinutes || 0;
      if (earlyLimit > 0) {
        const punct = computePunctuality(matchedCita.date, matchedCita.time, date, time);
        if (punct && punct.status === "a_tiempo" && Math.abs(punct.diffMinutes) > earlyLimit) {
          const minutesEarly = Math.abs(punct.diffMinutes);
          return json({
            error: `Tu cita es a las ${matchedCita.time}. Todavía es muy temprano (faltan ${minutesEarly} min) — el check-in se habilita ${earlyLimit} minutos antes de tu cita.`
          }, 403);
        }
      }
    }

    const id = `${scope}:arrival:${utcNow.getTime()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = {
      id, provider, driverName, plate, phone, transportType, orderNumber, customFields,
      ts: utcNow.getTime(), date, time, status: "esperando", dispatchedAt: null, unloadingStartedAt: null,
      geoLat: typeof data.geoLat === "number" ? data.geoLat : null,
      geoLng: typeof data.geoLng === "number" ? data.geoLng : null,
      geoDistance,
      linkedCitaId: null,
      punctuality: null,
      punctualityMinutes: null
    };

    // Vincula automáticamente con la cita programada encontrada arriba (misma orden de compra = llave principal).
    // Esto permite que "Programación de Citas" refleje en vivo el estado real del registro de llegada.
    if (matchedCita) {
      matchedCita.linkedArrivalId = id;
      matchedCita.status = "en_espera";
      const punctuality = computePunctuality(matchedCita.date, matchedCita.time, date, time);
      if (punctuality) {
        matchedCita.punctuality = punctuality.status;
        matchedCita.punctualityMinutes = punctuality.diffMinutes;
        record.punctuality = punctuality.status;
        record.punctualityMinutes = punctuality.diffMinutes;
      }
      const history = Array.isArray(matchedCita.history) ? matchedCita.history.slice() : [];
      history.push({ action: "vinculado", arrivalId: id, at: Date.now(), by: "check-in" });
      matchedCita.history = history;
      await kv.put(matchedCitaKey, JSON.stringify(matchedCita));
      record.linkedCitaId = matchedCitaKey;
    }

    await kv.put(id, JSON.stringify(record));

    if (settings && settings.webhookUrl) {
      try {
        await fetch(settings.webhookUrl, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...record, notifyEmail: settings.notifyEmail || "", notifyWhatsapp: settings.notifyWhatsapp || "" })
        });
      } catch {}
    }
    return json(record);
  }

  if (request.method === "PATCH") {
    const auth = await verifyStaffToken(request);
    if (!auth) return json({ error: "No autorizado" }, 403);
    const perms = permsFor(auth.role);
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);

    if (auth.global) {
      if (!scopeFromRecordId(data.id)) return json({ error: "Id de registro inválido" }, 400);
    } else {
      const scope = storageScope(auth.country, auth.facility);
      if (!data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);
    }

    const wantsFieldEdit = EDITABLE_FIELDS.some((key) => data[key] !== undefined);
    const wantsStatusChange = data.status !== undefined;
    if (wantsFieldEdit && !perms.editFields) return json({ error: "Tu rol no puede editar los datos del registro" }, 403);
    if (wantsStatusChange && !perms.changeStatus) return json({ error: "Tu rol no puede cambiar el estado" }, 403);

    const existing = await kv.get(data.id, "json");
    if (!existing) return json({ error: "Registro no encontrado" }, 404);
    if (data.status) {
      const validStatuses = ["esperando", "en_descarga", "despachado"];
      if (!validStatuses.includes(data.status)) return json({ error: "Estado inválido" }, 400);
      existing.status = data.status;
      if (data.status === "esperando") {
        existing.unloadingStartedAt = null;
        existing.dispatchedAt = null;
      } else if (data.status === "en_descarga") {
        if (!existing.unloadingStartedAt) existing.unloadingStartedAt = Date.now();
        existing.dispatchedAt = null;
      } else if (data.status === "despachado") {
        existing.dispatchedAt = Date.now();
      }
      // Si este registro está vinculado a una cita programada, refleja el mismo avance en la cita.
      if (existing.linkedCitaId) {
        const cita = await kv.get(existing.linkedCitaId, "json");
        if (cita) {
          const newCitaStatus = citaStatusFromArrivalStatus(data.status);
          if (newCitaStatus) {
            cita.status = newCitaStatus;
            const history = Array.isArray(cita.history) ? cita.history.slice() : [];
            history.push({ action: "estado_llegada", arrivalStatus: data.status, at: Date.now(), by: auth.username });
            cita.history = history;
            await kv.put(existing.linkedCitaId, JSON.stringify(cita));
          }
        }
      }
    }
    // Si se está corrigiendo la orden de compra, actualiza también el vínculo con Programación de Proveedores
    // (por ejemplo, si el transportista se equivocó al escribirla en el check-in).
    if (data.orderNumber !== undefined) {
      const newOrderNumber = (data.orderNumber || "").trim();
      if (newOrderNumber !== (existing.orderNumber || "")) {
        const scope = auth.global ? scopeFromRecordId(data.id) : storageScope(auth.country, auth.facility);
        // Desvincula la cita anterior, si tenía una — ese vínculo se basó en el número viejo (probablemente el equivocado).
        if (existing.linkedCitaId) {
          const oldCita = await kv.get(existing.linkedCitaId, "json");
          if (oldCita && oldCita.linkedArrivalId === data.id) {
            oldCita.status = "programado";
            delete oldCita.linkedArrivalId;
            delete oldCita.punctuality;
            delete oldCita.punctualityMinutes;
            const oldHistory = Array.isArray(oldCita.history) ? oldCita.history.slice() : [];
            oldHistory.push({ action: "desvinculado", reason: "orden_corregida", at: Date.now(), by: auth.username });
            oldCita.history = oldHistory;
            await kv.put(existing.linkedCitaId, JSON.stringify(oldCita));
          }
          existing.linkedCitaId = null;
          existing.punctuality = null;
          existing.punctualityMinutes = null;
        }
        // Busca una cita programada que coincida con la orden de compra corregida y la vincula.
        if (newOrderNumber && scope) {
          const citaKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
          for (const key of citaKeys) {
            const cita = await kv.get(key, "json");
            if (
              cita && cita.status !== "cancelado" && !cita.linkedArrivalId &&
              (cita.orderNumber || "").trim().toLowerCase() === newOrderNumber.toLowerCase()
            ) {
              cita.linkedArrivalId = data.id;
              cita.status = citaStatusFromArrivalStatus(existing.status) || "en_espera";
              const punctuality = computePunctuality(cita.date, cita.time, existing.date, existing.time);
              if (punctuality) {
                cita.punctuality = punctuality.status;
                cita.punctualityMinutes = punctuality.diffMinutes;
                existing.punctuality = punctuality.status;
                existing.punctualityMinutes = punctuality.diffMinutes;
              }
              const history = Array.isArray(cita.history) ? cita.history.slice() : [];
              history.push({ action: "vinculado", arrivalId: data.id, at: Date.now(), by: auth.username });
              cita.history = history;
              await kv.put(key, JSON.stringify(cita));
              existing.linkedCitaId = key;
              break;
            }
          }
        }
      }
    }
    for (const key of EDITABLE_FIELDS) { if (data[key] !== undefined) existing[key] = data[key]; }
    await kv.put(data.id, JSON.stringify(existing));
    return json(existing);
  }

  if (request.method === "DELETE") {
    const auth = await verifyStaffToken(request);
    const perms = permsFor(auth && auth.role);
    if (!auth || !perms.delete) return json({ error: "No autorizado. Solo Administración o el superusuario pueden eliminar registros de llegada." }, 403);
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);

    let scope;
    if (auth.global) {
      scope = scopeFromRecordId(data.id);
      if (!scope) return json({ error: "Id de registro inválido" }, 400);
    } else {
      scope = storageScope(auth.country, auth.facility);
      if (!data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);
    }

    // No se borra directamente: se respalda en la papelera antes de eliminar el original.
    const existing = await kv.get(data.id, "json");
    // Si el registro está ligado a una orden de compra, solo el superusuario puede eliminarlo.
    if (existing && existing.orderNumber && !perms.deleteLinked) {
      return json({ error: "Este registro está vinculado a una orden de compra. Solo el superusuario puede eliminarlo." }, 403);
    }
    if (existing) {
      // Si el registro estaba vinculado a una cita programada, la cita vuelve a "programado" (ya no hay llegada activa).
      if (existing.linkedCitaId) {
        const cita = await kv.get(existing.linkedCitaId, "json");
        if (cita && cita.linkedArrivalId === data.id) {
          cita.status = "programado";
          delete cita.linkedArrivalId;
          delete cita.punctuality;
          delete cita.punctualityMinutes;
          const history = Array.isArray(cita.history) ? cita.history.slice() : [];
          history.push({ action: "desvinculado", at: Date.now(), by: auth.username });
          cita.history = history;
          await kv.put(existing.linkedCitaId, JSON.stringify(cita));
        }
      }
      const archivedId = data.id.replace(":arrival:", ":archived:");
      const archivedRecord = {
        ...existing,
        originalId: data.id,
        archivedAt: Date.now(),
        archivedBy: auth.username
      };
      await kv.put(archivedId, JSON.stringify(archivedRecord));
    }
    await kv.delete(data.id);
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/arrivals-archive (papelera / backup de eliminados) ----------------
async function handleArrivalsArchive(request, env) {
  const kv = env.TORRE_KV;
  const auth = await verifyStaffToken(request);
  if (!auth || !permsFor(auth.role).manage) return json({ error: "No autorizado" }, 403);

  if (request.method === "GET") {
    const records = [];
    if (auth.global) {
      for (const s of allScopes()) {
        const keys = await kvListByPrefix(kv, `${s}:archived:`);
        for (const key of keys) {
          const val = await kv.get(key, "json");
          if (val) records.push({ ...val, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else if (Array.isArray(auth.multiScopes) && auth.multiScopes.length) {
      for (const s of auth.multiScopes) {
        const keys = await kvListByPrefix(kv, `${s}:archived:`);
        for (const key of keys) {
          const val = await kv.get(key, "json");
          if (val) records.push({ ...val, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else {
      const scope = storageScope(auth.country, auth.facility);
      const keys = await kvListByPrefix(kv, `${scope}:archived:`);
      for (const key of keys) { const val = await kv.get(key, "json"); if (val) records.push(val); }
    }
    records.sort((a, b) => (b.archivedAt || 0) - (a.archivedAt || 0));
    return json(records);
  }

  if (request.method === "POST") {
    // Restaura un registro archivado a la lista activa de llegadas.
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    const scope = scopeFromRecordId(data.id);
    if (!scope || !scopeAllowedForAuth(auth, scope)) return json({ error: "No autorizado" }, 403);
    const archived = await kv.get(data.id, "json");
    if (!archived) return json({ error: "Registro no encontrado en la papelera" }, 404);
    const restoreId = archived.originalId || data.id.replace(":archived:", ":arrival:");
    const { originalId, archivedAt, archivedBy, scopeKey, scopeLabel: _scopeLabel, ...restored } = archived;
    await kv.put(restoreId, JSON.stringify(restored));
    await kv.delete(data.id);
    return json({ ok: true, record: restored });
  }

  if (request.method === "DELETE") {
    // Elimina permanentemente de la papelera — reservado al superusuario global.
    if (auth.role !== "superadmin") return json({ error: "Solo el superusuario puede eliminar en definitiva" }, 403);
    const data = await readJson(request);
    if (!data || !data.id || !data.password) return json({ error: "Falta el id o la contraseña" }, 400);
    const scope = auth.global ? scopeFromRecordId(data.id) : storageScope(auth.country, auth.facility);
    if (!scope) return json({ error: "Id de registro inválido" }, 400);
    if (!auth.global && !data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);

    const userRec = await getUserRecord(kv, auth);
    if (!userRec) return json({ error: "Usuario no encontrado" }, 404);
    const ok = await verifyPassword(data.password, userRec.salt, userRec.passwordHash);
    if (!ok) return json({ error: "Contraseña incorrecta" }, 401);
    await kv.delete(data.id);
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/settings ----------------
async function handleSettings(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const scope = resolvePublicScope(request);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const settings = await kv.get(`${scope}:settings:config`, "json");
    return json(settings || {});
  }
  if (request.method === "POST") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const scope = resolveWriteScope(request, auth, null);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    await kv.put(`${scope}:settings:config`, JSON.stringify(data));
    return json({ ok: true });
  }
  return json({ error: "Método no permitido" }, 405);
}

async function handleDocks(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const scope = resolvePublicScope(request);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const docks = await kv.get(`${scope}:docks:list`, "json");
    return json(docks || []);
  }
  if (request.method === "POST") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !Array.isArray(data.docks)) return json({ error: "Formato inválido" }, 400);
    const scope = resolveWriteScope(request, auth, null);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const seen = new Set();
    const clean = [];
    for (const d of data.docks) {
      const name = (d || "").toString().trim();
      if (name && !seen.has(name.toLowerCase())) { seen.add(name.toLowerCase()); clean.push(name); }
    }
    await kv.put(`${scope}:docks:list`, JSON.stringify(clean));
    return json({ ok: true, docks: clean });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/provsched-config (horario semanal de programación de proveedores) ----------------
// Contraseña compartida requerida para cancelar/eliminar una programación de proveedor (no es la contraseña personal del usuario).
const PROVSCHED_DELETE_PASSWORD = "Compras2026";

const PROVSCHED_DEFAULT_CONFIG = {
  slotMinutes: 30,
  earlyCheckinMinutes: 0, // 0 = sin restricción; si se configura, el check-in solo se acepta desde ese número de minutos antes de la hora programada de la cita
  days: {
    mon: { enabled: true, start: "07:00", end: "17:00" },
    tue: { enabled: true, start: "07:00", end: "17:00" },
    wed: { enabled: true, start: "07:00", end: "17:00" },
    thu: { enabled: true, start: "07:00", end: "17:00" },
    fri: { enabled: true, start: "07:00", end: "17:00" },
    sat: { enabled: true, start: "07:00", end: "12:00" },
    sun: { enabled: false, start: "07:00", end: "12:00" }
  }
};

async function handleProvSchedConfig(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const auth = await verifyStaffToken(request);
    if (!auth) return json({ error: "No autorizado" }, 403);
    const scope = (auth.global || (Array.isArray(auth.multiScopes) && auth.multiScopes.length)) ? resolvePublicScope(request) : storageScope(auth.country, auth.facility);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const config = await kv.get(`${scope}:provsched:config`, "json");
    return json(config || PROVSCHED_DEFAULT_CONFIG);
  }
  if (request.method === "POST") {
    const auth = await verifyStaffToken(request);
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || typeof data.days !== "object") return json({ error: "Formato inválido" }, 400);
    const scope = resolveWriteScope(request, auth, null);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const slotMinutes = [15, 20, 30, 45, 60].includes(data.slotMinutes) ? data.slotMinutes : 30;
    const earlyCheckinMinutes = Math.max(0, Math.min(720, parseInt(data.earlyCheckinMinutes, 10) || 0));
    const dayKeys = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    const days = {};
    for (const k of dayKeys) {
      const d = data.days[k] || {};
      days[k] = {
        enabled: !!d.enabled,
        start: /^\d{2}:\d{2}$/.test(d.start) ? d.start : "07:00",
        end: /^\d{2}:\d{2}$/.test(d.end) ? d.end : "17:00"
      };
    }
    const config = { slotMinutes, earlyCheckinMinutes, days };
    await kv.put(`${scope}:provsched:config`, JSON.stringify(config));
    return json({ ok: true, config });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- Portal de proveedores ----------------
// Los proveedores son una identidad totalmente aparte del personal interno (admin/operador/etc):
// no tienen ningún permiso dentro del panel administrativo. Se guardan a nivel país (no por bodega),
// bajo la clave "{país}:provider:{usuario}", porque un proveedor puede entregar en cualquiera de las
// bodegas de ese país. Su token reutiliza signToken con role:"provider" — permsFor()/isAdminRole()
// no reconocen ese rol, así que automáticamente no obtiene ningún permiso de personal interno.
const PROVIDER_FACILITY_SENTINEL = "_PROVIDER";

function providerKey(country, username) {
  return `${country}:provider:${(username || "").trim().toLowerCase()}`;
}

// ---------------- /api/provider-auth (público: registro y login de proveedores) ----------------
async function handleProviderAuth(request, env) {
  if (request.method !== "POST") return json({ error: "Método no permitido" }, 405);
  const kv = env.TORRE_KV;
  const data = await readJson(request);
  if (!data || !data.action) return json({ error: "Falta la acción (registro o inicio de sesión)" }, 400);

  const country = VALID_COUNTRIES.includes(data.country) ? data.country : "GT";
  const username = (data.username || "").trim().toLowerCase();
  const password = data.password || "";

  if (data.action === "register") {
    const companyName = (data.companyName || "").trim();
    if (!username || username.length < 3) return json({ error: "El usuario debe tener al menos 3 caracteres" }, 400);
    if (!password || password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    if (!companyName) return json({ error: "El nombre de la empresa/proveedor es obligatorio" }, 400);
    const key = providerKey(country, username);
    const existing = await kv.get(key, "json");
    if (existing) return json({ error: "Ese usuario ya está registrado. Intenta iniciar sesión o elige otro usuario." }, 409);
    const salt = makeSalt();
    const passwordHash = await hashPassword(password, salt);
    const record = {
      username, salt, passwordHash, companyName,
      contactName: (data.contactName || "").trim() || null,
      phone: (data.phone || "").trim() || null,
      email: (data.email || "").trim() || null,
      country, createdAt: Date.now(), createdBy: "self"
    };
    await kv.put(key, JSON.stringify(record));
    const token = await signToken(username, "provider", country, PROVIDER_FACILITY_SENTINEL, false, false, null, null);
    return json({ ok: true, token, username, companyName });
  }

  if (data.action === "login") {
    if (!username || !password) return json({ error: "Usuario y contraseña son obligatorios" }, 400);
    const key = providerKey(country, username);
    const record = await kv.get(key, "json");
    if (!record) return json({ error: "Usuario o contraseña incorrectos" }, 401);
    const ok = await verifyPassword(password, record.salt, record.passwordHash);
    if (!ok) return json({ error: "Usuario o contraseña incorrectos" }, 401);
    const token = await signToken(username, "provider", record.country, PROVIDER_FACILITY_SENTINEL, false, false, null, null);
    return json({ ok: true, token, username, companyName: record.companyName });
  }

  return json({ error: "Acción inválida" }, 400);
}

// ---------------- /api/providers (personal interno: lista de proveedores registrados para el selector, y alta manual) ----------------
async function handleProviders(request, env) {
  const kv = env.TORRE_KV;
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role === "provider") return json({ error: "No autorizado" }, 403);

  if (request.method === "GET") {
    const country = VALID_COUNTRIES.includes(auth.country) ? auth.country : "GT";
    const keys = await kvListByPrefix(kv, `${country}:provider:`);
    const providers = [];
    for (const key of keys) {
      const p = await kv.get(key, "json");
      if (p) providers.push({ username: p.username, companyName: p.companyName, contactName: p.contactName, phone: p.phone, email: p.email });
    }
    providers.sort((a, b) => a.companyName.localeCompare(b.companyName));
    return json(providers);
  }

  if (request.method === "POST") {
    if (!isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const country = VALID_COUNTRIES.includes(auth.country) ? auth.country : "GT";
    const username = (data.username || "").trim().toLowerCase();
    const password = data.password || "";
    const companyName = (data.companyName || "").trim();
    if (!username || username.length < 3) return json({ error: "El usuario debe tener al menos 3 caracteres" }, 400);
    if (!password || password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    if (!companyName) return json({ error: "El nombre de la empresa/proveedor es obligatorio" }, 400);
    const key = providerKey(country, username);
    const existing = await kv.get(key, "json");
    if (existing) return json({ error: "Ese usuario ya existe" }, 409);
    const salt = makeSalt();
    const passwordHash = await hashPassword(password, salt);
    const record = {
      username, salt, passwordHash, companyName,
      contactName: (data.contactName || "").trim() || null,
      phone: (data.phone || "").trim() || null,
      email: (data.email || "").trim() || null,
      country, createdAt: Date.now(), createdBy: auth.username
    };
    await kv.put(key, JSON.stringify(record));
    return json({ ok: true, provider: { username, companyName } });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/provider-orders (el proveedor ve sus propias órdenes/citas y el estado de su carga) ----------------
async function handleProviderOrders(request, env) {
  if (request.method !== "GET") return json({ error: "Método no permitido" }, 405);
  const kv = env.TORRE_KV;
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "provider") return json({ error: "No autorizado" }, 403);

  const country = auth.country;
  const facilities = (COUNTRY_FACILITIES[country] || []).map((f) => f.code);
  const orders = [];
  for (const facilityCode of facilities) {
    const scope = `${country}:${facilityCode}`;
    const keys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
    for (const key of keys) {
      const c = await kv.get(key, "json");
      if (!c || c.providerId !== auth.username) continue;
      let arrival = null;
      if (c.linkedArrivalId) {
        const a = await kv.get(c.linkedArrivalId, "json");
        if (a) arrival = { status: a.status || "esperando", dock: a.dock || null, ts: a.ts || null, unloadingStartedAt: a.unloadingStartedAt || null, dispatchedAt: a.dispatchedAt || null };
      }
      orders.push({
        id: c.id, orderNumber: c.orderNumber, category: c.category,
        date: c.date, time: c.time, status: c.status,
        customFields: c.customFields || {}, createdAt: c.createdAt || null,
        scopeLabel: scopeLabel(scope), arrival
      });
    }
  }
  orders.sort((a, b) => (b.date + b.time).localeCompare(a.date + a.time));
  return json(orders);
}

// ---------------- /api/provsched-citas (programación de llegada de proveedores) ----------------
async function handleProvSchedCitas(request, env) {
  const kv = env.TORRE_KV;
  const auth = await verifyStaffToken(request);
  if (!auth) return json({ error: "No autorizado" }, 403);

  if (request.method === "GET") {
    const citas = [];
    if (auth.global) {
      for (const s of allScopes()) {
        const keys = await kvListByPrefix(kv, `${s}:provsched:cita:`);
        for (const key of keys) {
          const c = await kv.get(key, "json");
          if (c) citas.push({ ...c, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else if (Array.isArray(auth.multiScopes) && auth.multiScopes.length) {
      for (const s of auth.multiScopes) {
        const keys = await kvListByPrefix(kv, `${s}:provsched:cita:`);
        for (const key of keys) {
          const c = await kv.get(key, "json");
          if (c) citas.push({ ...c, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else if (COUNTRY_FACILITIES[auth.country] && COUNTRY_FACILITIES[auth.country].length) {
      // País con varias bodegas (ej. Guatemala: Atlas - Materiales, Atlas - Misceláneo y CD Santa Elena): cualquier admin de ese país
      // ve las citas de TODAS sus bodegas, para poder coordinarse entre ellas y filtrar por bodega.
      for (const f of COUNTRY_FACILITIES[auth.country]) {
        const s = `${auth.country}:${f.code}`;
        const keys = await kvListByPrefix(kv, `${s}:provsched:cita:`);
        for (const key of keys) {
          const c = await kv.get(key, "json");
          if (c) citas.push({ ...c, scopeKey: s, scopeLabel: scopeLabel(s) });
        }
      }
    } else {
      const scope = storageScope(auth.country, auth.facility);
      const keys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
      for (const key of keys) { const c = await kv.get(key, "json"); if (c) citas.push(c); }
    }
    citas.sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time));
    return json(citas);
  }

  const perms = permsFor(auth.role);
  if (!perms.editFields) return json({ error: "No autorizado" }, 403);

  if (request.method === "POST") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const scope = resolveWriteScope(request, auth, data);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);

    const orderNumber = (data.orderNumber || "").trim();
    const providerName = (data.providerName || "").trim();
    const providerId = (data.providerId || "").trim().toLowerCase() || null;
    const category = ["Compras Locales", "Contenedores"].includes(data.category) ? data.category : null;
    const date = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : null;
    const time = /^\d{2}:\d{2}$/.test(data.time) ? data.time : null;
    if (!orderNumber || !providerName || !category || !date || !time) {
      return json({ error: "Faltan datos: número de orden, proveedor, categoría, fecha y hora son obligatorios" }, 400);
    }
    if (data.documentData && typeof data.documentData === "string" && data.documentData.length > 7_000_000) {
      return json({ error: "El documento es demasiado grande (máximo ~5 MB)" }, 400);
    }

    // Cuántos camiones caben en el mismo horario depende de cuántos muelles tiene esa bodega —
    // con 1 muelle solo cabe 1 cita por horario; con 2+ muelles, caben tantas citas como muelles.
    const docksForScope = (await kv.get(`${scope}:docks:list`, "json")) || [];
    const docksCount = Math.max(1, docksForScope.length);

    // Verifica que el horario siga disponible (según el cupo de muelles) y que el número de orden no esté ya registrado (activo).
    const existingKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
    let sameSlotCount = 0;
    for (const key of existingKeys) {
      const c = await kv.get(key, "json");
      if (!c || !isActiveCitaStatus(c.status)) continue;
      if (c.date === date && c.time === time) sameSlotCount++;
      if ((c.orderNumber || "").trim().toLowerCase() === orderNumber.toLowerCase()) {
        return json({ error: `La orden de compra "${orderNumber}" ya está registrada. Cancela esa cita primero si necesitas reutilizar el número.` }, 409);
      }
    }
    if (sameSlotCount >= docksCount) {
      return json({ error: `Ese horario ya no está disponible: ya hay ${sameSlotCount} cita(s) programada(s) y solo hay ${docksCount} muelle(s). Elige otro horario.` }, 409);
    }

    const id = `${scope}:provsched:cita:${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const customFields = typeof data.customFields === "object" && data.customFields !== null ? data.customFields : {};
    const record = {
      id, orderNumber, providerName, providerId,
      documentName: (data.documentName || "").toString().slice(0, 200) || null,
      documentData: typeof data.documentData === "string" ? data.documentData : null,
      category, date, time, status: "programado",
      customFields,
      createdAt: Date.now(), createdBy: auth.username,
      history: []
    };
    await kv.put(id, JSON.stringify(record));
    return json({ ok: true, cita: record });
  }

  if (request.method === "PATCH") {
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    const scope = scopeFromRecordId(data.id);
    if (!scope || !citaScopeAllowedForAuth(auth, scope)) return json({ error: "No autorizado" }, 403);
    const existing = await kv.get(data.id, "json");
    if (!existing) return json({ error: "Programación no encontrada" }, 404);
    if (existing.status === "cancelado") return json({ error: "Esta programación fue cancelada. No se puede reprogramar." }, 400);

    const history = Array.isArray(existing.history) ? existing.history.slice() : [];

    // "No se presentó": una acción manual, independiente del check-in. Solo tiene sentido si nunca
    // llegó ningún camión vinculado a esta cita — si ya hay un registro de llegada real, no aplica.
    // Igual que "Cancelar cita", solo el rol Administración (o el superusuario) puede marcarla así.
    if (data.markNoShow === true) {
      if (auth.role !== "admin" && auth.role !== "superadmin") {
        return json({ error: "Solo un usuario con rol Administración puede marcar 'No se presentó'" }, 403);
      }
      if (existing.linkedArrivalId) {
        return json({ error: "Esta cita ya tiene un registro de llegada vinculado (el transportista sí llegó). No se puede marcar como 'No se presentó'." }, 400);
      }
      existing.status = "no_presento";
      history.push({ action: "no_presento", at: Date.now(), by: auth.username });
      existing.history = history;
      await kv.put(data.id, JSON.stringify(existing));
      return json({ ok: true, cita: existing });
    }

    if (data.date || data.time) {
      const newDate = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : existing.date;
      const newTime = /^\d{2}:\d{2}$/.test(data.time) ? data.time : existing.time;
      if (newDate !== existing.date || newTime !== existing.time) {
        const docksForScope = (await kv.get(`${scope}:docks:list`, "json")) || [];
        const docksCount = Math.max(1, docksForScope.length);
        const existingKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
        let sameSlotCount = 0;
        for (const key of existingKeys) {
          if (key === data.id) continue;
          const c = await kv.get(key, "json");
          if (c && isActiveCitaStatus(c.status) && c.date === newDate && c.time === newTime) sameSlotCount++;
        }
        if (sameSlotCount >= docksCount) {
          return json({ error: `Ese horario ya no está disponible: ya hay ${sameSlotCount} cita(s) programada(s) y solo hay ${docksCount} muelle(s). Elige otro horario.` }, 409);
        }
        history.push({ action: "reprogramado", from: { date: existing.date, time: existing.time }, to: { date: newDate, time: newTime }, at: Date.now(), by: auth.username });
        existing.date = newDate;
        existing.time = newTime;
        existing.status = "reprogramado";
      }
    }
    if (data.orderNumber) {
      const newOrderNumber = data.orderNumber.trim();
      if (newOrderNumber.toLowerCase() !== (existing.orderNumber || "").trim().toLowerCase()) {
        const existingKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
        for (const key of existingKeys) {
          if (key === data.id) continue;
          const c = await kv.get(key, "json");
          if (c && isActiveCitaStatus(c.status) && (c.orderNumber || "").trim().toLowerCase() === newOrderNumber.toLowerCase()) {
            return json({ error: `La orden de compra "${newOrderNumber}" ya está registrada. Cancela esa cita primero si necesitas reutilizar el número.` }, 409);
          }
        }
      }
      existing.orderNumber = newOrderNumber;
    }
    if (data.providerName) existing.providerName = data.providerName.trim();
    if (data.providerId !== undefined) existing.providerId = (data.providerId || "").trim().toLowerCase() || null;
    if (data.category && ["Compras Locales", "Contenedores"].includes(data.category)) existing.category = data.category;
    if (typeof data.customFields === "object" && data.customFields !== null) {
      existing.customFields = Object.assign({}, existing.customFields || {}, data.customFields);
    }
    if (data.documentData !== undefined) {
      if (data.documentData && typeof data.documentData === "string" && data.documentData.length > 7_000_000) {
        return json({ error: "El documento es demasiado grande (máximo ~5 MB)" }, 400);
      }
      existing.documentData = data.documentData || null;
      existing.documentName = (data.documentName || "").toString().slice(0, 200) || null;
    }
    existing.history = history;
    await kv.put(data.id, JSON.stringify(existing));
    return json({ ok: true, cita: existing });
  }

  if (request.method === "DELETE") {
    // Solo el superusuario puede cancelar/eliminar una programación, y requiere la contraseña de compras.
    if (auth.role !== "superadmin") {
      return json({ error: "Solo el superusuario puede eliminar una programación" }, 403);
    }
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    if (data.password !== PROVSCHED_DELETE_PASSWORD) {
      return json({ error: "Contraseña incorrecta" }, 401);
    }
    let scope;
    scope = scopeFromRecordId(data.id);
    if (!scope || !citaScopeAllowedForAuth(auth, scope)) return json({ error: "No autorizado" }, 403);
    const existing = await kv.get(data.id, "json");
    if (!existing) return json({ error: "Programación no encontrada" }, 404);
    const history = Array.isArray(existing.history) ? existing.history.slice() : [];
    history.push({ action: "cancelado", at: Date.now(), by: auth.username });
    existing.status = "cancelado";
    existing.history = history;
    await kv.put(data.id, JSON.stringify(existing));
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

async function handleCountries() {
  return json(VALID_COUNTRIES);
}

async function handleFacilities() {
  return json(COUNTRY_FACILITIES);
}

// ---------------- Migración de un solo uso: datos viejos (sin país) -> SV ----------------
async function handleMigrateLegacy(request, env) {
  const kv = env.TORRE_KV;
  const legacyPrefixes = ["user:", "arrival:", "settings:", "docks:", "formfields:", "suggestion:"];
  let cursor;
  let migrated = 0;
  let skipped = 0;
  do {
    const res = await kv.list({ cursor });
    for (const k of res.keys) {
      const name = k.name;
      if (/^(SV|GT|CR):/.test(name)) continue; // ya migrado o ya nuevo
      const isLegacy = legacyPrefixes.some((p) => name.startsWith(p));
      if (!isLegacy) continue;
      const newKey = `SV:${name}`;
      const alreadyThere = await kv.get(newKey);
      if (alreadyThere !== null) { skipped++; continue; }
      const value = await kv.get(name);
      if (value === null) continue;
      await kv.put(newKey, value);
      await kv.delete(name);
      migrated++;
    }
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  return json({ ok: true, migrated, skipped, note: "Datos antiguos migrados a El Salvador (SV). Este endpoint es seguro de visitar más de una vez." });
}

// ---------------- Migración de un solo uso: la bodega "GT:ATLAS" se dividió en dos bodegas nuevas ----------------
// (Atlas - Materiales de Construcción / Atlas - Misceláneo). Todo lo que ya existía bajo "GT:ATLAS:" se mueve
// a "GT:ATLAS_MATERIALES:" para no perder nada (usuarios, llegadas, citas, muelles, configuración, papelera, etc).
// Si algún registro pertenece en realidad a "Misceláneo", se puede mover manualmente después desde el panel.
async function handleMigrateAtlasSplit(request, env) {
  const kv = env.TORRE_KV;
  let cursor;
  let migrated = 0;
  let skipped = 0;
  do {
    const res = await kv.list({ cursor, prefix: "GT:ATLAS:" });
    for (const k of res.keys) {
      const name = k.name;
      const newKey = name.replace(/^GT:ATLAS:/, "GT:ATLAS_MATERIALES:");
      const alreadyThere = await kv.get(newKey);
      if (alreadyThere !== null) { skipped++; continue; }
      const value = await kv.get(name);
      if (value === null) continue;
      await kv.put(newKey, value);
      await kv.delete(name);
      migrated++;
    }
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  return json({ ok: true, migrated, skipped, note: "Datos de la antigua bodega 'CD Atlas' migrados a 'Atlas - Materiales de Construcción'. Este endpoint es seguro de visitar más de una vez." });
}

// ---------------- Respaldo automático (diario/semanal) ----------------

// Junta todo lo importante de todos los países/bodegas en un solo objeto, para guardar en R2.
async function buildFullBackup(env) {
  const kv = env.TORRE_KV;
  const backup = { generatedAt: Date.now(), scopes: {} };
  for (const s of allScopes()) {
    const arrivals = [];
    for (const k of await kvListByPrefix(kv, `${s}:arrival:`)) { const v = await kv.get(k, "json"); if (v) arrivals.push(v); }
    const archived = [];
    for (const k of await kvListByPrefix(kv, `${s}:archived:`)) { const v = await kv.get(k, "json"); if (v) archived.push(v); }
    const citas = [];
    for (const k of await kvListByPrefix(kv, `${s}:provsched:cita:`)) { const v = await kv.get(k, "json"); if (v) citas.push(v); }
    const users = [];
    for (const k of await kvListByPrefix(kv, `${s}:user:`)) {
      const v = await kv.get(k, "json");
      if (v) users.push({ username: v.username, role: v.role, createdAt: v.createdAt }); // nunca se incluye la contraseña
    }
    const docks = (await kv.get(`${s}:docks:list`, "json")) || [];
    const settings = (await kv.get(`${s}:settings:config`, "json")) || {};
    backup.scopes[s] = { label: scopeLabel(s), arrivals, archived, citas, users, docks, settings };
  }
  return backup;
}

function backupSummary(backup) {
  let arrivals = 0, archived = 0, citas = 0, users = 0;
  for (const s of Object.values(backup.scopes)) {
    arrivals += s.arrivals.length; archived += s.archived.length; citas += s.citas.length; users += s.users.length;
  }
  return { arrivals, archived, citas, users, scopes: Object.keys(backup.scopes).length };
}

// Envía el respaldo completo (todo el JSON) por el webhook configurado — sin depender de R2 ni de ningún
// almacenamiento pago. Desde Zapier/Make, el escenario puede guardar ese JSON donde se quiera (Drive, correo, etc.).
async function runScheduledBackup(env, period) {
  const backup = await buildFullBackup(env);
  const summary = backupSummary(backup);
  const now = new Date();
  const dateKey = now.toISOString().slice(0, 10);

  const cfg = await env.TORRE_KV.get(`${GLOBAL_SCOPE}:settings:backup`, "json");
  if (!cfg || !cfg.webhookUrl) {
    return { ok: false, sent: false, summary, note: "No hay webhook configurado en Configuración → Respaldo. El respaldo no se envió a ningún lado." };
  }
  try {
    await fetch(cfg.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "backup",
        period,
        date: dateKey,
        summary,
        notifyEmail: cfg.email || "",
        message: `Respaldo ${period} de Torre de Control (${dateKey}): ${summary.arrivals} llegadas, ${summary.archived} en papelera, ${summary.citas} citas, ${summary.users} usuarios, en ${summary.scopes} bodega(s).`,
        backup // el respaldo completo va aquí — tu escenario de Zapier/Make decide qué hacer con él (adjuntarlo a un correo, guardarlo en Drive, etc.)
      })
    });
    return { ok: true, sent: true, summary };
  } catch (e) {
    return { ok: false, sent: false, summary, note: "No se pudo entregar al webhook: " + (e && e.message ? e.message : "error desconocido") };
  }
}

// ---------------- /api/backup-settings (solo superusuario) ----------------
async function handleBackupSettings(request, env) {
  const auth = await verifyStaffToken(request);
  if (!auth || !auth.global) return json({ error: "Solo el superusuario puede ver/editar esto" }, 403);
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const cfg = (await kv.get(`${GLOBAL_SCOPE}:settings:backup`, "json")) || {};
    return json(cfg);
  }
  if (request.method === "POST") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const cfg = { email: (data.email || "").trim(), webhookUrl: (data.webhookUrl || "").trim() };
    await kv.put(`${GLOBAL_SCOPE}:settings:backup`, JSON.stringify(cfg));
    return json({ ok: true, ...cfg });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/backups (disparar un respaldo manual ahora, solo superusuario) ----------------
async function handleBackups(request, env) {
  const auth = await verifyStaffToken(request);
  if (!auth || !auth.global) return json({ error: "Solo el superusuario puede ver esto" }, 403);
  const url = new URL(request.url);

  if (request.method === "POST") {
    const period = url.searchParams.get("period") === "semanal" ? "semanal" : "diario";
    const result = await runScheduledBackup(env, period);
    return json(result);
  }

  return json({ error: "Método no permitido" }, 405);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const url = new URL(request.url);
    const path = url.pathname;

    // Todas las rutas de la API pasan por aquí. Si algo revienta dentro de un handler,
    // SIEMPRE devolvemos JSON (nunca la página de error genérica de Cloudflare, que es HTML
    // y rompe el `.json()` del frontend con "Unexpected token '<'").
    if (path.startsWith("/api/")) {
      try {
        if (path === "/api/auth") return await handleAuth(request, env);
        if (path === "/api/users") return await handleUsers(request, env);
        if (path === "/api/formfields") return await handleFormfields(request, env);
        if (path === "/api/provsched-formfields") return await handleProvSchedFormfields(request, env);
        if (path === "/api/suggestions") return await handleSuggestions(request, env);
        if (path === "/api/arrivals") return await handleArrivals(request, env);
        if (path === "/api/arrival-status") return await handleArrivalStatus(request, env);
        if (path === "/api/arrivals-archive") return await handleArrivalsArchive(request, env);
        if (path === "/api/settings") return await handleSettings(request, env);
        if (path === "/api/docks") return await handleDocks(request, env);
        if (path === "/api/provsched-config") return await handleProvSchedConfig(request, env);
        if (path === "/api/provsched-citas") return await handleProvSchedCitas(request, env);
        if (path === "/api/provider-auth") return await handleProviderAuth(request, env);
        if (path === "/api/providers") return await handleProviders(request, env);
        if (path === "/api/provider-orders") return await handleProviderOrders(request, env);
        if (path === "/api/backup-settings") return await handleBackupSettings(request, env);
        if (path === "/api/backups") return await handleBackups(request, env);
        if (path === "/api/countries") return handleCountries();
        if (path === "/api/facilities") return handleFacilities();
        if (path === "/api/migrate-legacy-to-sv") return await handleMigrateLegacy(request, env);
        if (path === "/api/migrate-atlas-split") return await handleMigrateAtlasSplit(request, env);
        return json({ error: "Ruta de API no encontrada" }, 404);
      } catch (err) {
        return json({ error: "Error interno del servidor: " + (err && err.message ? err.message : "desconocido") }, 500);
      }
    }

    // Ruta limpia /admin sin necesitar #panel
    if (path === "/admin") {
      const adminUrl = new URL(request.url);
      adminUrl.pathname = "/admin.html";
      return env.ASSETS.fetch(new Request(adminUrl, request));
    }

    // Nota: la ruta "/" se sirve directamente como index.html por los archivos estáticos (antes de
    // llegar aquí), así que el propio index.html decide client-side si debe mandar a /login o mostrar
    // el formulario de check-in (según si trae ?pais= en la URL). Ver el <script> al inicio de index.html.


    // Cualquier otra ruta: sirve los archivos estáticos (index.html, admin.html, assets)
    return env.ASSETS.fetch(request);
  },

  // Se ejecuta solo, sin que nadie tenga el navegador abierto, según los horarios definidos
  // en "triggers.crons" de wrangler.jsonc: todos los días a las 06:00 UTC, y los lunes también
  // se marca como respaldo "semanal" (mismo horario, pero se guarda en una carpeta aparte en R2).
  async scheduled(event, env, ctx) {
    const isMonday = event.cron === "0 6 * * 1";
    ctx.waitUntil(runScheduledBackup(env, "diario"));
    if (isMonday) ctx.waitUntil(runScheduledBackup(env, "semanal"));
  }
};
