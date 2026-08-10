import {
  hashPassword, verifyPassword, makeSalt, signToken, verifyToken,
  getTokenFromRequest, kvListByPrefix, CORS_HEADERS, json
} from "../lib/auth.js";

const EL_SALVADOR_OFFSET_MS = -6 * 60 * 60 * 1000;
const EDITABLE_FIELDS = ["provider", "driverName", "plate", "phone", "transportType", "customFields", "dock"];

const ROLE_PERMS = {
  admin:      { changeStatus: true, editFields: true, delete: true, manage: true },
  operador:   { changeStatus: true, editFields: true, delete: false, manage: false },
  asistente:  { changeStatus: true, editFields: false, delete: false, manage: false },
  viewer:     { changeStatus: false, editFields: false, delete: false, manage: false },
  conductor:  { changeStatus: false, editFields: false, delete: false, manage: false }
};
function permsFor(role) { return ROLE_PERMS[role] || ROLE_PERMS.viewer; }

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

// ---------------- /api/auth ----------------
async function handleAuth(request, env) {
  if (request.method !== "POST") return json({ error: "Método no permitido" }, 405);
  const data = await readJson(request);
  if (!data) return json({ error: "JSON inválido" }, 400);

  const kv = env.TORRE_KV;
  const userKeys = await kvListByPrefix(kv, "user:");
  let hasAdmin = false;
  for (const key of userKeys) {
    const u = await kv.get(key, "json");
    if (u && u.role === "admin") { hasAdmin = true; break; }
  }
  if (!hasAdmin) {
    const salt = makeSalt();
    await kv.put("user:admin", JSON.stringify({
      username: "admin",
      passwordHash: await hashPassword("Torre2026", salt),
      salt, role: "admin", createdAt: Date.now()
    }));
  }

  const username = (data.username || "").trim().toLowerCase();
  const password = data.password || "";
  if (!username || !password) return json({ error: "Usuario y contraseña son obligatorios" }, 400);

  const user = await kv.get(`user:${username}`, "json");
  if (!user) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const token = await signToken(user.username, user.role);
  return json({ token, username: user.username, role: user.role });
}

// ---------------- /api/users ----------------
async function handleUsers(request, env) {
  const auth = await verifyToken(getTokenFromRequest(request));
  if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
  const kv = env.TORRE_KV;

  if (request.method === "GET") {
    const keys = await kvListByPrefix(kv, "user:");
    const users = [];
    for (const key of keys) {
      const u = await kv.get(key, "json");
      if (u) users.push({ username: u.username, role: u.role, createdAt: u.createdAt });
    }
    users.sort((a, b) => a.username.localeCompare(b.username));
    return json(users);
  }

  if (request.method === "POST") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const username = (data.username || "").trim().toLowerCase();
    const password = data.password || "";
    const validRoles = ["admin", "operador", "asistente", "viewer", "conductor"];
    const role = validRoles.includes(data.role) ? data.role : "viewer";
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) {
      return json({ error: "El usuario debe tener 3-30 caracteres (letras, números, puntos o guiones)" }, 400);
    }
    if (password.length < 4) return json({ error: "La contraseña debe tener al menos 4 caracteres" }, 400);
    const existing = await kv.get(`user:${username}`, "json");
    if (existing) return json({ error: `El usuario "${username}" ya existe. Elimínalo primero si quieres reemplazarlo.` }, 400);
    const salt = makeSalt();
    await kv.put(`user:${username}`, JSON.stringify({
      username, passwordHash: await hashPassword(password, salt), salt, role, createdAt: Date.now()
    }));
    return json({ ok: true });
  }

  if (request.method === "PATCH") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const username = (data.username || "").trim().toLowerCase();
    const newPassword = data.newPassword || "";
    if (newPassword.length < 4) return json({ error: "La contraseña debe tener al menos 4 caracteres" }, 400);
    const existing = await kv.get(`user:${username}`, "json");
    if (!existing) return json({ error: "Usuario no encontrado" }, 404);
    const salt = makeSalt();
    existing.passwordHash = await hashPassword(newPassword, salt);
    existing.salt = salt;
    await kv.put(`user:${username}`, JSON.stringify(existing));
    return json({ ok: true });
  }

  if (request.method === "DELETE") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const username = (data.username || "").trim().toLowerCase();
    if (username === auth.username) return json({ error: "No puedes eliminar tu propio usuario" }, 400);
    await kv.delete(`user:${username}`);
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/formfields ----------------
async function handleFormfields(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const fields = await kv.get("formfields:custom", "json");
    return json(fields || []);
  }
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !Array.isArray(data.fields)) return json({ error: "Formato inválido" }, 400);
    const clean = data.fields
      .map((f) => ({ id: (f.id || "").trim(), label: (f.label || "").trim(), type: f.type === "tel" ? "tel" : "text", required: !!f.required }))
      .filter((f) => f.id && f.label);
    await kv.put("formfields:custom", JSON.stringify(clean));
    return json({ ok: true, fields: clean });
  }
  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/suggestions ----------------
async function handleSuggestions(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth) return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const message = (data.message || "").trim();
    if (!message) return json({ error: "Escribe tu sugerencia" }, 400);
    const id = `suggestion:${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = { id, message, from: auth.username, ts: Date.now() };
    await kv.put(id, JSON.stringify(record));
    const settings = await kv.get("settings:config", "json");
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
    if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
    const keys = await kvListByPrefix(kv, "suggestion:");
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
    const keys = await kvListByPrefix(kv, "arrival:");
    const records = [];
    for (const key of keys) { const val = await kv.get(key, "json"); if (val) records.push(val); }
    records.sort((a, b) => a.ts - b.ts);
    return json(records);
  }

  if (request.method === "POST") {
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    const provider = (data.provider || "").trim();
    const driverName = (data.driverName || "").trim();
    const plate = (data.plate || "").trim();
    const phone = (data.phone || "").trim();
    const transportType = (data.transportType || "").trim();
    const customFields = typeof data.customFields === "object" && data.customFields !== null ? data.customFields : {};

    const settings = await kv.get("settings:config", "json");
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
    const id = `arrival:${utcNow.getTime()}-${Math.random().toString(36).slice(2, 7)}`;
    const record = {
      id, provider, driverName, plate, phone, transportType, customFields,
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
    if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !data.id) return json({ error: "Falta id" }, 400);
    await kv.delete(data.id);
    return json({ ok: true });
  }

  return json({ error: "Método no permitido" }, 405);
}

// ---------------- /api/settings ----------------
async function handleSettings(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const settings = await kv.get("settings:config", "json");
    return json(settings || {});
  }
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data) return json({ error: "JSON inválido" }, 400);
    await kv.put("settings:config", JSON.stringify(data));
    return json({ ok: true });
  }
  return json({ error: "Método no permitido" }, 405);
}

async function handleDocks(request, env) {
  const kv = env.TORRE_KV;
  if (request.method === "GET") {
    const docks = await kv.get("docks:list", "json");
    return json(docks || []);
  }
  if (request.method === "POST") {
    const auth = await verifyToken(getTokenFromRequest(request));
    if (!auth || auth.role !== "admin") return json({ error: "No autorizado" }, 403);
    const data = await readJson(request);
    if (!data || !Array.isArray(data.docks)) return json({ error: "Formato inválido" }, 400);
    const seen = new Set();
    const clean = [];
    for (const d of data.docks) {
      const name = (d || "").toString().trim();
      if (name && !seen.has(name.toLowerCase())) { seen.add(name.toLowerCase()); clean.push(name); }
    }
    await kv.put("docks:list", JSON.stringify(clean));
    return json({ ok: true, docks: clean });
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

    if (path === "/api/auth") return handleAuth(request, env);
    if (path === "/api/users") return handleUsers(request, env);
    if (path === "/api/formfields") return handleFormfields(request, env);
    if (path === "/api/suggestions") return handleSuggestions(request, env);
    if (path === "/api/arrivals") return handleArrivals(request, env);
    if (path === "/api/settings") return handleSettings(request, env);
    if (path === "/api/docks") return handleDocks(request, env);

    // Ruta limpia /admin sin necesitar #panel
    if (path === "/admin") {
      const adminUrl = new URL(request.url);
      adminUrl.pathname = "/admin.html";
      return env.ASSETS.fetch(new Request(adminUrl, request));
    }

    // Cualquier otra ruta: sirve los archivos estáticos (index.html, admin.html, assets)
    return env.ASSETS.fetch(request);
  }
};
