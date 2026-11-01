// Venta.iPhone.Buceo — servidor de la tienda en Cloudflare Workers.
// - Sirve la tienda (index.html) con el catálogo guardado en KV ya incluido.
// - /admin lleva al panel "Editar tienda" (entra con la contraseña ADMIN_PASSWORD).
// - /api/* guarda el catálogo y las fotos en KV (binding STORE).

const enc = new TextEncoder();
const MAX_STORE_BYTES = 1_000_000; // catálogo en texto (las fotos van aparte)
const MAX_IMG_BYTES = 5_000_000;
const IMG_TYPES = ['image/webp', 'image/jpeg', 'image/png'];
const SESSION_DAYS = 30;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const fail = (status, error) => json({ error }, status);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const b64u = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const fromB64u = (s) => atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
async function sha(s) {
  return b64u(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Sesión firmada con la contraseña: si cambiás la contraseña, se cierran todas las sesiones.
async function makeToken(env) {
  const payload = b64u(enc.encode(JSON.stringify({ exp: Date.now() + SESSION_DAYS * 864e5 })));
  return payload + '.' + (await hmac('vib-session:' + env.ADMIN_PASSWORD, payload));
}
async function isAdmin(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const good = await hmac('vib-session:' + env.ADMIN_PASSWORD, payload);
  if (!sameText(sig, good)) return false;
  try {
    return JSON.parse(fromB64u(payload)).exp > Date.now();
  } catch {
    return false;
  }
}

function validStore(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return 'Formato de catálogo inválido.';
  if (!s.settings || typeof s.settings !== 'object') return 'Faltan los ajustes de la tienda.';
  if (!Array.isArray(s.products) || s.products.length > 1000) return 'La lista de productos no es válida.';
  if (!Array.isArray(s.faqs) || s.faqs.length > 200) return 'La lista de preguntas no es válida.';
  if (!Number.isInteger(s.nextId)) return 'Falta el contador de productos.';
  for (const p of s.products) {
    if (!p || !Number.isInteger(p.id) || typeof p.name !== 'string' || typeof p.price !== 'number' || !Array.isArray(p.images)) {
      return 'Hay un producto con datos incompletos.';
    }
  }
  return '';
}

async function readBody(request, max) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > max) return null;
  const buf = await request.arrayBuffer();
  return buf.byteLength > max ? null : buf;
}

async function handleApi(request, env, url) {
  if (!env.STORE) return fail(500, 'Falta conectar el espacio de datos (KV "STORE") en Cloudflare.');
  const path = url.pathname.replace(/^\/api/, '');
  const method = request.method;

  if (path === '/store' && method === 'GET') {
    const data = await env.STORE.get('store');
    if (!data) return json({ empty: true }); // todavía no se guardó nada: se usa el catálogo de la página
    return new Response(data, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
  }

  if (path === '/login' && method === 'POST') {
    if (!env.ADMIN_PASSWORD) return fail(500, 'Falta configurar la contraseña (ADMIN_PASSWORD) en Cloudflare.');
    let body = {};
    try {
      body = await request.json();
    } catch {
      /* cuerpo vacío */
    }
    const pw = typeof body.password === 'string' ? body.password : '';
    if (!sameText(await sha(pw), await sha(env.ADMIN_PASSWORD))) {
      await sleep(1200); // frena intentos repetidos
      return fail(401, 'Contraseña incorrecta.');
    }
    return json({ token: await makeToken(env) });
  }

  if (path === '/me' && method === 'GET') {
    return (await isAdmin(request, env)) ? json({ ok: true }) : fail(401, 'Sesión vencida.');
  }

  if (path === '/store' && method === 'PUT') {
    if (!(await isAdmin(request, env))) return fail(401, 'Sesión vencida.');
    const buf = await readBody(request, MAX_STORE_BYTES);
    if (!buf) return fail(413, 'El catálogo es demasiado grande.');
    let s;
    try {
      s = JSON.parse(new TextDecoder().decode(buf));
    } catch {
      return fail(400, 'Formato de catálogo inválido.');
    }
    const problem = validStore(s);
    if (problem) return fail(400, problem);
    s.updatedAt = Date.now();
    const text = JSON.stringify(s);
    await env.STORE.put('store', text);
    // Copia de respaldo de la versión anterior, por si hay que volver atrás.
    await env.STORE.put('store:backup:' + new Date().toISOString().slice(0, 10), text);
    return json({ ok: true, updatedAt: s.updatedAt });
  }

  if (path === '/img' && method === 'POST') {
    if (!(await isAdmin(request, env))) return fail(401, 'Sesión vencida.');
    const type = (request.headers.get('content-type') || '').split(';')[0].trim();
    if (!IMG_TYPES.includes(type)) return fail(415, 'La foto tiene que ser JPG, PNG o WEBP.');
    const buf = await readBody(request, MAX_IMG_BYTES);
    if (!buf || !buf.byteLength) return fail(413, 'La foto pesa demasiado (máximo 5 MB).');
    const id = crypto.randomUUID();
    await env.STORE.put('img:' + id, buf, { metadata: { type } });
    return json({ url: '/img/' + id });
  }

  // ----- Solicitudes "Vendé o permutá tu iPhone" -----
  if (path === '/requests' && method === 'POST') return createRequest(request, env);
  if (path === '/requests' && method === 'GET') {
    if (!(await isAdmin(request, env))) return fail(401, 'Sesión vencida.');
    return json({ requests: await listRequests(env) });
  }
  let m;
  if ((m = /^\/requests\/(r\d{13}-[0-9a-f]{8})$/.exec(path))) {
    if (!(await isAdmin(request, env))) return fail(401, 'Sesión vencida.');
    const key = 'req:' + m[1];
    const rec = await env.STORE.get(key, 'json');
    if (!rec) return fail(404, 'La solicitud ya no existe.');
    if (method === 'PATCH') {
      let body = {};
      try {
        body = await request.json();
      } catch {
        /* vacío */
      }
      if (!REQ_STATUS.includes(body.status)) return fail(400, 'Estado inválido.');
      rec.status = body.status;
      await env.STORE.put(key, JSON.stringify(rec));
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await Promise.all([env.STORE.delete(key), ...rec.photos.map((id) => env.STORE.delete('rimg:' + id))]);
      return json({ ok: true });
    }
  }
  if ((m = /^\/rimg\/([0-9a-f-]{36})$/.exec(path)) && method === 'GET') {
    if (!(await isAdmin(request, env))) return fail(401, 'Sesión vencida.');
    const { value, metadata } = await env.STORE.getWithMetadata('rimg:' + m[1], { type: 'arrayBuffer' });
    if (!value) return fail(404, 'Foto no encontrada.');
    return new Response(value, { headers: { 'content-type': (metadata && metadata.type) || 'image/jpeg', 'cache-control': 'private, max-age=86400' } });
  }

  return fail(404, 'No existe.');
}

const REQ_STATUS = ['nueva', 'contactado', 'cerrada'];
const REQ_MAX_PHOTOS = 4;
const REQ_MAX_PHOTO_BYTES = 4_000_000;
const REQ_PER_HOUR = 6; // por conexión, para frenar abusos
const clip = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');

async function createRequest(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'local';
  const rlKey = 'rl:req:' + ip;
  const used = Number((await env.STORE.get(rlKey)) || 0);
  if (used >= REQ_PER_HOUR) return fail(429, 'Recibimos varias solicitudes seguidas. Probá de nuevo en un rato o escribinos por WhatsApp.');

  let form;
  try {
    form = await request.formData();
  } catch {
    return fail(400, 'No se pudo leer el formulario.');
  }
  if (clip(form.get('website'), 10)) return json({ ok: true }); // trampa para robots
  let d = {};
  try {
    d = JSON.parse(form.get('data') || '{}');
  } catch {
    return fail(400, 'Datos inválidos.');
  }
  const type = d.type === 'permuta' ? 'permuta' : d.type === 'venta' ? 'venta' : '';
  const model = clip(d.model, 40);
  const storage = clip(d.storage, 12);
  const battery = Number(d.battery);
  const name = clip(d.name, 80);
  const phone = clip(d.phone, 30);
  const digits = phone.replace(/\D/g, '');
  if (!type) return fail(400, 'Elegí si querés vender o permutar.');
  if (!model) return fail(400, 'Elegí el modelo de tu iPhone.');
  if (!storage) return fail(400, 'Elegí la capacidad.');
  if (!Number.isInteger(battery) || battery < 1 || battery > 100) return fail(400, 'La batería va de 1 a 100 %.');
  if (!name) return fail(400, 'Escribí tu nombre.');
  if (digits.length < 8 || digits.length > 15) return fail(400, 'Revisá tu número de WhatsApp.');

  const files = form.getAll('photos').filter((f) => f && typeof f === 'object' && 'arrayBuffer' in f);
  if (!files.length) return fail(400, 'Agregá al menos una foto del iPhone.');
  if (files.length > REQ_MAX_PHOTOS) return fail(400, `Podés mandar hasta ${REQ_MAX_PHOTOS} fotos.`);
  for (const f of files) {
    if (!IMG_TYPES.includes(f.type)) return fail(415, 'Las fotos tienen que ser JPG, PNG o WEBP.');
    if (f.size > REQ_MAX_PHOTO_BYTES) return fail(413, 'Una de las fotos pesa demasiado.');
  }

  const now = Date.now();
  const id = 'r' + String(9999999999999 - now).padStart(13, '0') + '-' + crypto.randomUUID().slice(0, 8);
  const photos = [];
  for (const f of files) {
    const pid = crypto.randomUUID();
    await env.STORE.put('rimg:' + pid, await f.arrayBuffer(), { metadata: { type: f.type } });
    photos.push(pid);
  }
  const rec = {
    id, type, model, storage, battery, name, phone,
    wanted: type === 'permuta' ? clip(d.wanted, 120) : '',
    details: clip(d.details, 800),
    photos, status: 'nueva', createdAt: now,
  };
  await env.STORE.put('req:' + id, JSON.stringify(rec));
  await env.STORE.put(rlKey, String(used + 1), { expirationTtl: 3600 });
  return json({ ok: true, id });
}

async function listRequests(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.STORE.list({ prefix: 'req:', cursor, limit: 1000 });
    out.push(...page.keys.map((k) => k.name));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && out.length < 300);
  // Las claves ya vienen de la más nueva a la más vieja.
  const recs = await Promise.all(out.slice(0, 200).map((k) => env.STORE.get(k, 'json')));
  return recs.filter(Boolean);
}

async function serveImage(env, id) {
  if (!env.STORE || !/^[0-9a-f-]{36}$/.test(id)) return new Response('No encontrada', { status: 404 });
  const { value, metadata } = await env.STORE.getWithMetadata('img:' + id, { type: 'arrayBuffer', cacheTtl: 86400 });
  if (!value) return new Response('No encontrada', { status: 404 });
  return new Response(value, {
    headers: { 'content-type': (metadata && metadata.type) || 'image/webp', 'cache-control': 'public, max-age=31536000, immutable' },
  });
}

// La tienda con el catálogo guardado ya incluido (carga instantánea y sin parpadeo).
async function servePage(request, env) {
  const res = await env.ASSETS.fetch(new Request(new URL('/', request.url)));
  if (!res.ok) return res;
  let html = await res.text();
  const data = env.STORE ? await env.STORE.get('store') : null;
  if (data) {
    const safe = data.replace(/</g, '\\u003c');
    html = html.replace(/(<script type="application\/json" id="store-data">)[\s\S]*?(<\/script>)/, (_, a, b) => a + safe + b);
  }
  return new Response(request.method === 'HEAD' ? null : html, {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (p.startsWith('/api/')) return await handleApi(request, env, url);
      if (p.startsWith('/img/')) return await serveImage(env, p.slice(5));
      if (p === '/admin' || p === '/admin/' || p === '/editar') return Response.redirect(new URL('/#editar', url), 302);
      if ((p === '/' || p === '/index.html') && (request.method === 'GET' || request.method === 'HEAD') && env.ASSETS) {
        return await servePage(request, env);
      }
      return env.ASSETS ? env.ASSETS.fetch(request) : new Response('No encontrada', { status: 404 });
    } catch (e) {
      console.error(e);
      return p.startsWith('/api/') ? fail(500, 'Error del servidor. Probá de nuevo en unos segundos.') : new Response('Error', { status: 500 });
    }
  },
};
