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
