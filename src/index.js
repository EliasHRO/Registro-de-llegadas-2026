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
  superadmin: { changeStatus: true, editFields: true, delete: true, manage: true },
  admin:      { changeStatus: true, editFields: true, delete: false, manage: true },
  operador:   { changeStatus: true, editFields: true, delete: false, manage: false },
  asistente:  { changeStatus: true, editFields: false, delete: false, manage: false },
  viewer:     { changeStatus: false, editFields: false, delete: false, manage: false },
  conductor:  { changeStatus: false, editFields: false, delete: false, manage: false }
};
function permsFor(role) { return ROLE_PERMS[role] || ROLE_PERMS.viewer; }
function isAdminRole(role) { return role === "admin" || role === "superadmin"; }

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
  const auth = await verifyToken(getTokenFromRequest(request));
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
    const auth = await verifyToken(getTokenFromRequest(request));
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
    const auth = await verifyToken(getTokenFromRequest(request));
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

// ---------------- /api/suggestions ----------------
async function handleSuggestions(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
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
    const auth = await verifyToken(getTokenFromRequest(request));
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
async function handleArrivals(request, env) {
  const kv = env.TORRE_KV;

  if (request.method === "GET") {
    const auth = await verifyToken(getTokenFromRequest(request));
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
    const id = `${scope}:arrival:${utcNow.getTime()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = {
      id, provider, driverName, plate, phone, transportType, orderNumber, customFields,
      ts: utcNow.getTime(), date, time, status: "esperando", dispatchedAt: null, unloadingStartedAt: null,
      geoLat: typeof data.geoLat === "number" ? data.geoLat : null,
      geoLng: typeof data.geoLng === "number" ? data.geoLng : null,
      geoDistance
    };
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
    const auth = await verifyToken(getTokenFromRequest(request));
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
    }
    for (const key of EDITABLE_FIELDS) { if (data[key] !== undefined) existing[key] = data[key]; }
    await kv.put(data.id, JSON.stringify(existing));
    return json(existing);
  }

  if (request.method === "DELETE") {
    const auth = await verifyToken(getTokenFromRequest(request));
    const perms = permsFor(auth && auth.role);
    if (!auth || !perms.delete) return json({ error: "No autorizado. Solo el superusuario puede eliminar registros de llegada." }, 403);
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
    if (existing) {
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
  const auth = await verifyToken(getTokenFromRequest(request));
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
    let scope;
    if (auth.global) {
      scope = scopeFromRecordId(data.id);
      if (!scope) return json({ error: "Id de registro inválido" }, 400);
    } else {
      scope = storageScope(auth.country, auth.facility);
      if (!data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);
    }
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
    const auth = await verifyToken(getTokenFromRequest(request));
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
    const auth = await verifyToken(getTokenFromRequest(request));
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
const PROVSCHED_DEFAULT_CONFIG = {
  slotMinutes: 30,
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
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth) return json({ error: "No autorizado" }, 403);
    const scope = (auth.global || (Array.isArray(auth.multiScopes) && auth.multiScopes.length)) ? resolvePublicScope(request) : storageScope(auth.country, auth.facility);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const config = await kv.get(`${scope}:provsched:config`, "json");
    return json(config || PROVSCHED_DEFAULT_CONFIG);
  }
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth || !isAdminRole(auth.role)) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || typeof data.days !== "object") return json({ error: "Formato inválido" }, 400);
    const scope = resolveWriteScope(request, auth, null);
    if (!scope) return json({ error: "País/bodega inválido o no especificado" }, 400);
    const slotMinutes = [15, 20, 30, 45, 60].includes(data.slotMinutes) ? data.slotMinutes : 30;
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
    const config = { slotMinutes, days };
    await kv.put(`${scope}:provsched:config`, JSON.stringify(config));
    return json({ ok: true, config });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/provsched-citas (programación de llegada de proveedores) ----------------
async function handleProvSchedCitas(request, env) {
  const kv = env.TORRE_KV;
  const auth = await verifyToken(getTokenFromRequest(request));
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
    const category = ["Compras Locales", "Contenedores"].includes(data.category) ? data.category : null;
    const date = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : null;
    const time = /^\d{2}:\d{2}$/.test(data.time) ? data.time : null;
    if (!orderNumber || !providerName || !category || !date || !time) {
      return json({ error: "Faltan datos: número de orden, proveedor, categoría, fecha y hora son obligatorios" }, 400);
    }
    if (data.documentData && typeof data.documentData === "string" && data.documentData.length > 7_000_000) {
      return json({ error: "El documento es demasiado grande (máximo ~5 MB)" }, 400);
    }

    // Verifica que el horario siga disponible y que el número de orden no esté ya registrado (activo).
    const existingKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
    for (const key of existingKeys) {
      const c = await kv.get(key, "json");
      if (!c || c.status === "cancelado") continue;
      if (c.date === date && c.time === time) {
        return json({ error: "Ese horario ya no está disponible. Elige otro." }, 409);
      }
      if ((c.orderNumber || "").trim().toLowerCase() === orderNumber.toLowerCase()) {
        return json({ error: `La orden de compra "${orderNumber}" ya está registrada. Cancela esa cita primero si necesitas reutilizar el número.` }, 409);
      }
    }

    const id = `${scope}:provsched:cita:${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = {
      id, orderNumber, providerName,
      documentName: (data.documentName || "").toString().slice(0, 200) || null,
      documentData: typeof data.documentData === "string" ? data.documentData : null,
      category, date, time, status: "programado",
      createdAt: Date.now(), createdBy: auth.username,
      history: []
    };
    await kv.put(id, JSON.stringify(record));
    return json({ ok: true, cita: record });
  }

  if (request.method === "PATCH") {
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    let scope;
    if (auth.global || (Array.isArray(auth.multiScopes) && auth.multiScopes.length)) {
      scope = scopeFromRecordId(data.id);
      if (!scope || !scopeAllowedForAuth(auth, scope)) return json({ error: "No autorizado" }, 403);
    } else {
      scope = storageScope(auth.country, auth.facility);
      if (!data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);
    }
    const existing = await kv.get(data.id, "json");
    if (!existing) return json({ error: "Programación no encontrada" }, 404);
    if (existing.status === "cancelado") return json({ error: "Esta programación fue cancelada. No se puede reprogramar." }, 400);

    const history = Array.isArray(existing.history) ? existing.history.slice() : [];

    if (data.date || data.time) {
      const newDate = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : existing.date;
      const newTime = /^\d{2}:\d{2}$/.test(data.time) ? data.time : existing.time;
      if (newDate !== existing.date || newTime !== existing.time) {
        const existingKeys = await kvListByPrefix(kv, `${scope}:provsched:cita:`);
        for (const key of existingKeys) {
          if (key === data.id) continue;
          const c = await kv.get(key, "json");
          if (c && c.status !== "cancelado" && c.date === newDate && c.time === newTime) {
            return json({ error: "Ese horario ya no está disponible. Elige otro." }, 409);
          }
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
          if (c && c.status !== "cancelado" && (c.orderNumber || "").trim().toLowerCase() === newOrderNumber.toLowerCase()) {
            return json({ error: `La orden de compra "${newOrderNumber}" ya está registrada. Cancela esa cita primero si necesitas reutilizar el número.` }, 409);
          }
        }
      }
      existing.orderNumber = newOrderNumber;
    }
    if (data.providerName) existing.providerName = data.providerName.trim();
    if (data.category && ["Compras Locales", "Contenedores"].includes(data.category)) existing.category = data.category;
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
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    let scope;
    if (auth.global || (Array.isArray(auth.multiScopes) && auth.multiScopes.length)) {
      scope = scopeFromRecordId(data.id);
      if (!scope || !scopeAllowedForAuth(auth, scope)) return json({ error: "No autorizado" }, 403);
    } else {
      scope = storageScope(auth.country, auth.facility);
      if (!data.id.startsWith(`${scope}:`)) return json({ error: "No autorizado" }, 403);
    }
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

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/auth") return handleAuth(request, env);
    if (path === "/api/users") return handleUsers(request, env);
    if (path === "/api/formfields") return handleFormfields(request, env);
    if (path === "/api/suggestions") return handleSuggestions(request, env);
    if (path === "/api/arrivals") return handleArrivals(request, env);
    if (path === "/api/arrivals-archive") return handleArrivalsArchive(request, env);
    if (path === "/api/settings") return handleSettings(request, env);
    if (path === "/api/docks") return handleDocks(request, env);
    if (path === "/api/provsched-config") return handleProvSchedConfig(request, env);
    if (path === "/api/provsched-citas") return handleProvSchedCitas(request, env);
    if (path === "/api/countries") return handleCountries();
    if (path === "/api/facilities") return handleFacilities();
    if (path === "/api/migrate-legacy-to-sv") return handleMigrateLegacy(request, env);

    // Ruta limpia /admin sin necesitar #panel
    if (path === "/admin") {
      const adminUrl = new URL(request.url);
      adminUrl.pathname = "/admin.html";
      return env.ASSETS.fetch(new Request(adminUrl, request));
    }

    // La página principal (dominio raíz, sin parámetros de check-in) manda directo al panel admin,
    // en vez de mostrar el formulario de check-in. Los QR de check-in siguen funcionando porque
    // llevan ?pais=...(&bodega=...) en la URL, y esos casos sí se sirven como check-in normalmente.
    if (path === "/" && !url.searchParams.has("pais")) {
      return Response.redirect(new URL("/admin", request.url).toString(), 302);
    }

    // Cualquier otra ruta: sirve los archivos estáticos (index.html, admin.html, assets)
    return env.ASSETS.fetch(request);
  }
};
