import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';

app.use(express.json({ limit: '32kb' }));

// Load public Firebase Web config (prefer user custom config if present)
let firebaseWebConfig = null;
for (const cfgFile of ['firebase-custom-config.json', 'firebase-applet-config.json']) {
  const cfgPath = path.join(__dirname, cfgFile);
  if (!fs.existsSync(cfgPath)) continue;
  try {
    const raw = fs.readFileSync(cfgPath, 'utf8');
    const parsed = JSON.parse(raw);
    firebaseWebConfig = {
      apiKey: parsed.apiKey,
      authDomain: parsed.authDomain,
      projectId: parsed.projectId,
      firestoreDatabaseId: parsed.firestoreDatabaseId || '',
      storageBucket: parsed.storageBucket,
      appId: parsed.appId,
      messagingSenderId: parsed.messagingSenderId || '',
    };
    break;
  } catch (err) {
    console.warn(`${cfgFile} unreadable:`, err.message);
  }
}

const BLOCKED_PATHS = new Set([
  '/server.js',
  '/package.json',
  '/package-lock.json',
  '/bun.lock',
  '/metadata.json',
  '/firebase-applet-config.json',
  '/firebase-custom-config.json',
  '/firebase-blueprint.json',
  '/firestore.rules',
  '/firestore.rules.test.ts',
  '/security_spec.md',
  '/eslint.config.js',
]);

app.use((req, res, next) => {
  if (BLOCKED_PATHS.has(req.path) || req.path.startsWith('/node_modules')) {
    return res.status(404).end();
  }
  next();
});

// Public Firebase client configuration endpoint
app.get('/api/firebase-config', (_req, res) => {
  if (!firebaseWebConfig) {
    return res.status(503).json({ error: 'Firebase configuration not available' });
  }
  return res.json(firebaseWebConfig);
});

// Token verification cache (short TTL to avoid repeated lookup latency)
const tokenCache = new Map();
const TOKEN_CACHE_TTL_MS = 60_000;

async function verifyFirebaseIdToken(idToken) {
  if (!firebaseWebConfig?.apiKey || !idToken || typeof idToken !== 'string' || idToken.length > 4096) {
    return null;
  }

  const cached = tokenCache.get(idToken);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.user;
  }

  try {
    const resp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseWebConfig.apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    const user = data?.users?.[0];
    if (!user?.localId || !user.emailVerified) return null;

    const info = { uid: user.localId, email: user.email || '' };
    tokenCache.set(idToken, { user: info, expiresAt: Date.now() + TOKEN_CACHE_TTL_MS });
    if (tokenCache.size > 200) {
      const oldestKey = tokenCache.keys().next().value;
      tokenCache.delete(oldestKey);
    }
    return info;
  } catch {
    return null;
  }
}

async function requireFirebaseAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Autenticación requerida' });
  }
  const token = authHeader.slice(7).trim();
  const user = await verifyFirebaseIdToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Token de Firebase inválido o cuenta no verificada' });
  }
  req.firebaseUser = user;
  next();
}

// ntfy topic validation & sender (JSON publish supports full UTF-8 Spanish accents & emojis)
const NTFY_TOPIC_REGEX = /^[a-zA-Z0-9_-]{6,64}$/;

function isValidTopic(topic) {
  return typeof topic === 'string' && NTFY_TOPIC_REGEX.test(topic);
}

async function sendNtfyPush({ topic, title, message, priority = 3, tags = [] }) {
  if (!isValidTopic(topic)) {
    throw new Error('Tema ntfy inválido (usa 6-64 letras, números, - o _)');
  }
  const resp = await fetch('https://ntfy.sh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      topic,
      title: String(title || 'Plan de Pablo').slice(0, 120),
      message: String(message || '').slice(0, 500),
      priority: Math.max(1, Math.min(5, Number(priority) || 3)),
      tags: Array.isArray(tags) ? tags.slice(0, 5) : [],
    }),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`ntfy respondió ${resp.status}: ${text.slice(0, 120)}`);
  }
}

// Server-side scheduled timers per authenticated user (fires even if iPad is locked)
const activeTimers = new Map();

function clearUserScheduledTimer(uid) {
  const existing = activeTimers.get(uid);
  if (existing) {
    if (existing.fiveMinTimeout) clearTimeout(existing.fiveMinTimeout);
    if (existing.endTimeout) clearTimeout(existing.endTimeout);
    activeTimers.delete(uid);
  }
}

function formatApproxEndTime(remainingSeconds) {
  const endDate = new Date(Date.now() + remainingSeconds * 1000);
  return endDate.toLocaleTimeString('es-ES', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Madrid',
  });
}

function scheduleUserTimerNotifications(uid, { topic, walletName, remainingSeconds, notifyFiveMin, notifyOnEnd }) {
  clearUserScheduledTimer(uid);
  if (!isValidTopic(topic) || remainingSeconds <= 0) return;

  const entry = {
    topic,
    walletName,
    endAt: Date.now() + remainingSeconds * 1000,
    fiveMinTimeout: null,
    endTimeout: null,
  };

  if (notifyFiveMin && remainingSeconds > 300) {
    const delayMs = (remainingSeconds - 300) * 1000;
    entry.fiveMinTimeout = setTimeout(() => {
      sendNtfyPush({
        topic,
        title: `Quedan 5 min · ${walletName}`,
        message: `A Pablo le quedan 5 minutos de ${walletName}.`,
        priority: 3,
        tags: ['hourglass_flowing_sand'],
      }).catch(err => console.warn('ntfy 5-min push failed:', err.message));
    }, delayMs);
  }

  if (notifyOnEnd) {
    const delayMs = remainingSeconds * 1000;
    entry.endTimeout = setTimeout(() => {
      activeTimers.delete(uid);
      sendNtfyPush({
        topic,
        title: `Tiempo terminado · ${walletName}`,
        message: `Se ha acabado el tiempo disponible de ${walletName} de Pablo.`,
        priority: 4,
        tags: ['alarm_clock'],
      }).catch(err => console.warn('ntfy end push failed:', err.message));
    }, delayMs);
  }

  activeTimers.set(uid, entry);
}

app.post('/api/ntfy/test', requireFirebaseAuth, async (req, res) => {
  const { topic } = req.body || {};
  if (!isValidTopic(topic)) {
    return res.status(400).json({ error: 'El tema ntfy debe tener entre 6 y 64 caracteres (letras, números, - o _).' });
  }
  try {
    await sendNtfyPush({
      topic,
      title: 'Prueba conectada · Plan de Pablo',
      message: '¡Perfecto! Ya recibirás avisos aquí en tu iPhone cuando Pablo inicie, pause o termine su tiempo.',
      priority: 3,
      tags: ['checkered_flag', 'white_check_mark'],
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

app.post('/api/ntfy/timer/start', requireFirebaseAuth, async (req, res) => {
  const { topic, walletName, remainingSeconds, notifyOnStart, notifyFiveMin, notifyOnEnd } = req.body || {};
  const remSec = Math.max(0, Math.min(36000, Math.floor(Number(remainingSeconds) || 0)));
  const safeName = String(walletName || 'Pantalla').slice(0, 40);

  if (!isValidTopic(topic) || remSec <= 0) {
    clearUserScheduledTimer(req.firebaseUser.uid);
    return res.json({ ok: true, scheduled: false });
  }

  scheduleUserTimerNotifications(req.firebaseUser.uid, {
    topic,
    walletName: safeName,
    remainingSeconds: remSec,
    notifyFiveMin: Boolean(notifyFiveMin),
    notifyOnEnd: Boolean(notifyOnEnd),
  });

  if (notifyOnStart) {
    const mins = Math.max(1, Math.ceil(remSec / 60));
    const approxEnd = formatApproxEndTime(remSec);
    try {
      await sendNtfyPush({
        topic,
        title: `Tiempo iniciado · ${safeName}`,
        message: `Pablo ha activado ${mins} min de ${safeName} (termina aprox. a las ${approxEnd}).`,
        priority: 3,
        tags: ['arrow_forward'],
      });
    } catch (err) {
      console.warn('ntfy start push failed:', err.message);
    }
  }

  return res.json({ ok: true, scheduled: true });
});

app.post('/api/ntfy/timer/sync', requireFirebaseAuth, (req, res) => {
  const { topic, walletName, remainingSeconds, notifyFiveMin, notifyOnEnd } = req.body || {};
  const remSec = Math.max(0, Math.min(36000, Math.floor(Number(remainingSeconds) || 0)));
  const safeName = String(walletName || 'Pantalla').slice(0, 40);

  if (!isValidTopic(topic) || remSec <= 0) {
    clearUserScheduledTimer(req.firebaseUser.uid);
    return res.json({ ok: true, scheduled: false });
  }

  scheduleUserTimerNotifications(req.firebaseUser.uid, {
    topic,
    walletName: safeName,
    remainingSeconds: remSec,
    notifyFiveMin: Boolean(notifyFiveMin),
    notifyOnEnd: Boolean(notifyOnEnd),
  });

  return res.json({ ok: true, scheduled: true });
});

app.post('/api/ntfy/timer/pause', requireFirebaseAuth, async (req, res) => {
  const { topic, walletName, remainingSeconds, notifyOnPause } = req.body || {};
  const remSec = Math.max(0, Math.min(36000, Math.floor(Number(remainingSeconds) || 0)));
  const safeName = String(walletName || 'Pantalla').slice(0, 40);

  clearUserScheduledTimer(req.firebaseUser.uid);

  if (notifyOnPause && isValidTopic(topic)) {
    const mins = Math.floor(remSec / 60);
    const secs = remSec % 60;
    const remText = mins > 0 ? `${mins}m ${String(secs).padStart(2, '0')}s` : `${secs}s`;
    try {
      await sendNtfyPush({
        topic,
        title: `Tiempo pausado · ${safeName}`,
        message: `Pablo ha pausado ${safeName}. Le quedan ${remText}.`,
        priority: 2,
        tags: ['pause_button'],
      });
    } catch (err) {
      console.warn('ntfy pause push failed:', err.message);
    }
  }

  return res.json({ ok: true });
});

app.post('/api/ntfy/timer/cancel', requireFirebaseAuth, (req, res) => {
  clearUserScheduledTimer(req.firebaseUser.uid);
  return res.json({ ok: true });
});

app.get('/manifest.webmanifest', (_req, res) => {
  res.type('application/manifest+json; charset=utf-8');
  res.sendFile(path.join(__dirname, 'manifest.webmanifest'));
});

app.get('/sw.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.type('application/javascript; charset=utf-8');
  res.sendFile(path.join(__dirname, 'sw.js'));
});

app.use(express.static(__dirname, { index: 'index.html' }));

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
