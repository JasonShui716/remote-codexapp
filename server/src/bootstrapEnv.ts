import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import dotenv from 'dotenv';

// Ensure `.env` is loaded even if the server is started with an unexpected cwd
// (e.g. via systemd WorkingDirectory at repo root).
//
// Priority:
// 1) Explicit ENV_FILE (absolute or relative to process.cwd()).
// 2) `<serverRoot>/.env` where serverRoot is `server/`.
// 3) `<repoRoot>/.env` for backward-compat (older setups).
const serverRootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRootDir = path.resolve(serverRootDir, '..');
const envFile = (() => {
  const explicit = (process.env.ENV_FILE || '').trim();
  if (explicit) return path.isAbsolute(explicit) ? explicit : path.resolve(process.cwd(), explicit);
  const preferred = path.resolve(serverRootDir, '.env');
  if (fs.existsSync(preferred)) return preferred;
  return path.resolve(repoRootDir, '.env');
})();

try {
  if (fs.existsSync(envFile)) {
    dotenv.config({ path: envFile, override: false });
  }
} catch {
  // Best-effort: production may inject env vars via systemd/docker without any .env file.
}
