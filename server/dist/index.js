import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import crypto from 'node:crypto';
import { z } from 'zod';
import qrcode from 'qrcode-terminal';
import { authenticator } from 'otplib';
import { readEnv } from './config.js';
import { MemoryStore } from './store.js';
import { CodexManager } from './codexManager.js';
const env = readEnv();
const store = new MemoryStore({
    sessionTtlMs: env.SESSION_TTL_MS,
    otpTtlMs: env.OTP_TTL_MS,
    maxOtpAttempts: 5,
    otpLockMs: 15 * 60 * 1000
});
const codex = new CodexManager();
setInterval(() => store.sweep(), 30_000).unref();
function isRecord(v) {
    return typeof v === 'object' && v !== null;
}
function parseReasoningEffort(v) {
    if (v === 'low' || v === 'medium' || v === 'high' || v === 'xhigh')
        return v;
    return null;
}
function uniqueReasoningEfforts(items) {
    return Array.from(new Set(items));
}
function readCodexModelOptions() {
    const codexHome = (process.env.CODEX_HOME || '').trim() || path.join(os.homedir(), '.codex');
    const cachePath = path.join(codexHome, 'models_cache.json');
    try {
        const raw = fs.readFileSync(cachePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!isRecord(parsed) || !Array.isArray(parsed.models))
            return [];
        const out = [];
        for (const item of parsed.models) {
            if (!isRecord(item))
                continue;
            if (typeof item.visibility === 'string' && item.visibility !== 'list')
                continue;
            const slug = typeof item.slug === 'string' ? item.slug.trim() : '';
            if (!slug)
                continue;
            const displayName = typeof item.display_name === 'string' && item.display_name.trim()
                ? item.display_name.trim()
                : slug;
            const description = typeof item.description === 'string' && item.description.trim()
                ? item.description.trim()
                : undefined;
            const defaultReasoningEffort = parseReasoningEffort(item.default_reasoning_level);
            const reasoningEfforts = uniqueReasoningEfforts(Array.isArray(item.supported_reasoning_levels)
                ? item.supported_reasoning_levels
                    .map((x) => (isRecord(x) ? parseReasoningEffort(x.effort) : null))
                    .filter((x) => Boolean(x))
                : []);
            if (!reasoningEfforts.length && defaultReasoningEffort) {
                reasoningEfforts.push(defaultReasoningEffort);
            }
            out.push({
                slug,
                displayName,
                description,
                defaultReasoningEffort: defaultReasoningEffort || undefined,
                reasoningEfforts
            });
        }
        return out;
    }
    catch {
        return [];
    }
}
const codexModelOptions = readCodexModelOptions();
if (!codexModelOptions.length && env.CODEX_MODEL) {
    const fallbackEffort = parseReasoningEffort(env.CODEX_REASONING_EFFORT);
    codexModelOptions.push({
        slug: env.CODEX_MODEL,
        displayName: env.CODEX_MODEL,
        defaultReasoningEffort: fallbackEffort || undefined,
        reasoningEfforts: fallbackEffort ? [fallbackEffort] : []
    });
}
const codexReasoningEffortOptions = uniqueReasoningEfforts(codexModelOptions.flatMap((m) => m.reasoningEfforts));
// TOTP provisioning lock: once a user successfully logs in via TOTP, we write a marker file.
// After that, QR/URI should not be retrievable or printed again.
const totpProvisionPath = path.isAbsolute(env.TOTP_PROVISION_FILE)
    ? env.TOTP_PROVISION_FILE
    : path.resolve(process.cwd(), env.TOTP_PROVISION_FILE);
function isTotpProvisioned() {
    try {
        return fs.existsSync(totpProvisionPath);
    }
    catch {
        return false;
    }
}
function markTotpProvisioned() {
    try {
        fs.writeFileSync(totpProvisionPath, JSON.stringify({ provisionedAt: Date.now() }, null, 2) + '\n', { flag: 'wx' });
    }
    catch (e) {
        // Ignore if already exists.
        if (e?.code !== 'EEXIST')
            throw e;
    }
}
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser(env.SESSION_SECRET));
if (env.WEB_ORIGIN) {
    app.use(cors({
        origin: env.WEB_ORIGIN,
        credentials: true
    }));
}
function getSessionId(req) {
    const sid = req.signedCookies?.sid || req.cookies?.sid;
    if (!sid)
        return null;
    const s = store.getSession(sid);
    if (!s)
        return null;
    store.refreshSession(sid);
    return s.id;
}
function requireAuth(req, res) {
    const sid = getSessionId(req);
    if (!sid) {
        res.status(401).json({ ok: false, error: 'unauthorized' });
        return null;
    }
    return sid;
}
app.get('/api/health', (_req, res) => {
    res.json({ ok: true, time: Date.now() });
});
app.get('/api/auth/mode', (_req, res) => {
    res.json({ ok: true, mode: env.AUTH_MODE });
});
app.get('/api/auth/totp/status', (_req, res) => {
    if (env.AUTH_MODE !== 'totp') {
        return res.json({ ok: true, enabled: false, provisioned: false });
    }
    return res.json({ ok: true, enabled: true, provisioned: isTotpProvisioned() });
});
app.get('/api/auth/totp/uri', (_req, res) => {
    if (env.AUTH_MODE !== 'totp') {
        return res.status(400).json({ ok: false, error: 'wrong_mode' });
    }
    if (!env.TOTP_SECRET) {
        return res.status(500).json({ ok: false, error: 'totp_not_configured' });
    }
    if (isTotpProvisioned()) {
        // Global one-time QR: once someone successfully logged in, do not allow retrieving URI again.
        return res.status(404).json({ ok: false, error: 'provisioned' });
    }
    if (!env.EXPOSE_TOTP_URI) {
        return res.status(404).json({ ok: false, error: 'disabled' });
    }
    const uri = authenticator.keyuri(env.TOTP_ACCOUNT, env.TOTP_ISSUER, env.TOTP_SECRET);
    res.json({ ok: true, uri });
});
app.get('/api/me', (req, res) => {
    const sid = getSessionId(req);
    // Returning 401 here creates a noisy console error on the login screen.
    // Keep /api/me as a "soft auth" probe (200 + ok:false) and reserve 401s for protected endpoints.
    if (!sid)
        return res.json({ ok: false });
    res.json({
        ok: true,
        sessionId: sid,
        activeChatId: store.getActiveChatId(sid) || undefined,
        expiresInMs: env.SESSION_TTL_MS
    });
});
app.get('/api/defaults', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    res.json({
        ok: true,
        defaults: {
            model: env.CODEX_MODEL || null,
            reasoningEffort: env.CODEX_REASONING_EFFORT || null,
            cwd: env.CODEX_CWD,
            sandbox: env.CODEX_SANDBOX,
            approvalPolicy: env.CODEX_APPROVAL_POLICY,
            modelOptions: codexModelOptions,
            reasoningEffortOptions: codexReasoningEffortOptions
        }
    });
});
function expandUserPath(p) {
    const home = os.homedir();
    return p
        .replace(/^~(?=\/|$)/, home)
        .replace(/\$\{HOME\}/g, home)
        .replace(/\$HOME\b/g, home);
}
function computeCwdRoots() {
    const raw = env.CWD_ROOTS ? env.CWD_ROOTS.split(',').map((s) => s.trim()).filter(Boolean) : [env.CODEX_CWD];
    const abs = raw.map((p) => {
        const x = expandUserPath(p);
        return path.isAbsolute(x) ? x : path.resolve(x);
    });
    const out = [];
    for (const p of abs) {
        try {
            const st = fs.statSync(p);
            if (!st.isDirectory())
                continue;
            const real = fs.realpathSync(p);
            out.push({ abs: p, real, label: p === env.CODEX_CWD ? 'Default' : path.basename(p) || p });
        }
        catch {
            // ignore invalid roots
        }
    }
    // Always ensure at least CODEX_CWD exists as a root if possible.
    if (!out.length) {
        try {
            const real = fs.realpathSync(env.CODEX_CWD);
            out.push({ abs: env.CODEX_CWD, real, label: 'Default' });
        }
        catch {
            // nothing
        }
    }
    return out;
}
const cwdRoots = computeCwdRoots();
function isWithinRoot(real, rootReal) {
    if (real === rootReal)
        return true;
    const pref = rootReal.endsWith(path.sep) ? rootReal : rootReal + path.sep;
    return real.startsWith(pref);
}
function resolveAllowedDir(p) {
    try {
        const expanded = expandUserPath(p);
        const abs = path.isAbsolute(expanded) ? expanded : path.resolve(env.CODEX_CWD, expanded);
        const st = fs.statSync(abs);
        if (!st.isDirectory())
            return { ok: false, error: 'not_dir' };
        const real = fs.realpathSync(abs);
        const ok = cwdRoots.some((r) => isWithinRoot(real, r.real));
        if (!ok)
            return { ok: false, error: 'outside_root' };
        return { ok: true, real };
    }
    catch {
        return { ok: false, error: 'not_found' };
    }
}
app.get('/api/fs/roots', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    res.json({ ok: true, roots: cwdRoots.map((r) => ({ path: r.abs, label: r.label })) });
});
app.get('/api/fs/ls', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const p = typeof req.query.path === 'string' ? req.query.path : '';
    const showHidden = req.query.hidden === '1';
    const dir = p || env.CODEX_CWD;
    const resolved = resolveAllowedDir(dir);
    if (!resolved.ok)
        return res.status(400).json({ ok: false, error: resolved.error });
    const entries = fs.readdirSync(resolved.real, { withFileTypes: true })
        .filter((d) => (showHidden ? true : !d.name.startsWith('.')))
        .map((d) => ({
        name: d.name,
        type: d.isDirectory() ? 'dir' : d.isFile() ? 'file' : 'other'
    }))
        .sort((a, b) => {
        if (a.type !== b.type)
            return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
    res.json({ ok: true, path: resolved.real, entries });
});
app.post('/api/auth/otp/request', (_req, res) => {
    if (env.AUTH_MODE !== 'otp') {
        return res.status(400).json({ ok: false, error: 'wrong_mode' });
    }
    const { challenge, otp } = store.createOtpChallenge();
    // Intentionally only logs OTP server-side.
    // In production you'd deliver via email/SMS/etc.
    // We include challenge id in response.
    console.log(`[OTP] challenge=${challenge.id} otp=${otp} (expires in ${Math.round(env.OTP_TTL_MS / 1000)}s)`);
    res.json({ ok: true, challengeId: challenge.id, expiresInMs: env.OTP_TTL_MS });
});
const VerifySchema = z.object({
    challengeId: z.string().min(1),
    otp: z.string().regex(/^\d{6}$/)
});
app.post('/api/auth/otp/verify', (req, res) => {
    if (env.AUTH_MODE !== 'otp') {
        return res.status(400).json({ ok: false, error: 'wrong_mode' });
    }
    const parsed = VerifySchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ ok: false, error: 'bad_request' });
    }
    const r = store.verifyOtpChallenge(parsed.data.challengeId, parsed.data.otp);
    if (!r.ok) {
        return res.status(401).json({ ok: false, error: r.error ?? 'invalid' });
    }
    const session = store.createSession();
    res.cookie('sid', session.id, {
        httpOnly: true,
        sameSite: 'lax',
        signed: true,
        secure: false, // set true behind HTTPS
        maxAge: env.SESSION_TTL_MS
    });
    res.json({ ok: true, sessionId: session.id, expiresInMs: env.SESSION_TTL_MS });
});
const TotpVerifySchema = z.object({
    code: z.string().regex(/^\d{6}$/)
});
app.post('/api/auth/totp/verify', (req, res) => {
    if (env.AUTH_MODE !== 'totp') {
        return res.status(400).json({ ok: false, error: 'wrong_mode' });
    }
    if (!env.TOTP_SECRET) {
        return res.status(500).json({ ok: false, error: 'totp_not_configured' });
    }
    const parsed = TotpVerifySchema.safeParse(req.body);
    if (!parsed.success) {
        return res.status(400).json({ ok: false, error: 'bad_request' });
    }
    authenticator.options = { window: 1 };
    const ok = authenticator.check(parsed.data.code, env.TOTP_SECRET);
    if (!ok) {
        return res.status(401).json({ ok: false, error: 'invalid' });
    }
    // First successful TOTP login permanently disables QR/URI for this server instance (and across restarts).
    markTotpProvisioned();
    // All devices that scan the same QR share a single logical "account session".
    // Cookie is signed, so clients can't forge other ids.
    const fixedSid = (() => {
        const raw = `${env.SESSION_SECRET}:${env.TOTP_SECRET}:${env.TOTP_ISSUER}:${env.TOTP_ACCOUNT}`;
        const h = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24);
        return `totp_${h}`;
    })();
    const session = store.getOrCreateSessionWithId(fixedSid);
    res.cookie('sid', session.id, {
        httpOnly: true,
        sameSite: 'lax',
        signed: true,
        secure: false,
        maxAge: env.SESSION_TTL_MS
    });
    res.json({ ok: true, sessionId: session.id, expiresInMs: env.SESSION_TTL_MS });
});
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('sid');
    res.json({ ok: true });
});
app.post('/api/chats', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chat = store.createChat(sid);
    res.json({ ok: true, chatId: chat.id });
});
app.get('/api/chats', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    res.json({ ok: true, chats: store.listChats(sid) });
});
app.get('/api/chats/:chatId', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chat = store.getChat(sid, req.params.chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    store.setActiveChatId(sid, req.params.chatId);
    res.json({ ok: true, chat });
});
app.get('/api/chats/:chatId/runtime', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chat = store.getChat(sid, req.params.chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    const rt = reconcileRuntimeStatus(sid, req.params.chatId);
    res.json({ ok: true, status: rt.status, lastEventId: rt.lastEventId, updatedAt: rt.updatedAt });
});
function writeSseEvent(res, e) {
    res.write(`id: ${e.id}\n`);
    res.write(`event: ${e.event}\n`);
    res.write(`data: ${JSON.stringify(e.data)}\n\n`);
}
function reconcileRuntimeStatus(sid, chatId) {
    const rt = store.getStreamRuntime(sid, chatId);
    if (rt.status === 'running') {
        if (!codex.isBusy(sid, chatId)) {
            // Self-heal stale "running" states if stream completion was missed.
            store.appendStreamEvent(sid, chatId, 'done', { ok: true, reconciled: true });
            return store.getStreamRuntime(sid, chatId);
        }
        const staleMs = Date.now() - rt.updatedAt;
        if (staleMs >= env.STUCK_RUNNING_ABORT_MS && !codex.hasPendingApproval(sid, chatId)) {
            // If Codex appears stuck with no updates for too long, auto-abort to avoid
            // forcing users to manually click Abort for a stale run state.
            const aborted = codex.abort(sid, chatId);
            if (aborted.ok) {
                store.appendStreamEvent(sid, chatId, 'codex_event', {
                    type: 'stuck_running_auto_abort',
                    staleMs,
                    thresholdMs: env.STUCK_RUNNING_ABORT_MS
                });
            }
        }
    }
    return rt;
}
app.get('/api/chats/:chatId/stream', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    const afterParam = req.query.after ? Number(req.query.after) : undefined;
    const lastEventIdHeader = req.header('last-event-id') ?? req.header('Last-Event-ID');
    const afterHeader = lastEventIdHeader ? Number(lastEventIdHeader) : undefined;
    // Prefer Last-Event-ID so EventSource reconnect works even if caller uses a static `after=` query param.
    const after = Number.isFinite(afterHeader) ? afterHeader : (Number.isFinite(afterParam) ? afterParam : 0);
    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();
    const rt = reconcileRuntimeStatus(sid, chatId);
    for (const e of store.listStreamEventsSince(sid, chatId, after)) {
        writeSseEvent(res, e);
    }
    if (rt.status !== 'running') {
        res.end();
        return;
    }
    const unsub = store.subscribeStream(sid, chatId, (e) => {
        try {
            writeSseEvent(res, e);
            if (e.event === 'done' || e.event === 'turn_error' || e.event === 'error') {
                unsub();
                res.end();
            }
        }
        catch {
            // client likely disconnected
            unsub();
        }
    });
    res.on('close', () => {
        unsub();
    });
});
const SendSchema = z.object({
    text: z.string().min(1).max(20_000),
    model: z.string().min(1).optional()
});
const SettingsSchema = z.object({
    model: z.union([z.string().min(1), z.null()]).optional(),
    reasoningEffort: z.union([z.enum(['low', 'medium', 'high', 'xhigh']), z.null()]).optional(),
    cwd: z.union([z.string().min(1), z.null()]).optional(),
    sandbox: z.union([z.enum(['read-only', 'workspace-write', 'danger-full-access']), z.null()]).optional(),
    approvalPolicy: z.union([z.enum(['untrusted', 'on-failure', 'on-request', 'never']), z.null()]).optional()
});
const ActiveChatSchema = z.object({
    chatId: z.string().min(1)
});
app.get('/api/session/active-chat', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    res.json({ ok: true, chatId: store.getActiveChatId(sid) || null });
});
app.post('/api/session/active-chat', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const parsed = ActiveChatSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ ok: false, error: 'bad_request' });
    const ok = store.setActiveChatId(sid, parsed.data.chatId);
    if (!ok)
        return res.status(404).json({ ok: false, error: 'not_found' });
    res.json({ ok: true });
});
async function startChatTurn(opts) {
    const chat = store.getChat(opts.sid, opts.chatId);
    if (!chat)
        throw new Error('not_found');
    if (codex.isBusy(opts.sid, opts.chatId))
        throw new Error('chat_busy');
    store.appendMessage(opts.sid, opts.chatId, { role: 'user', text: opts.text });
    const assistantMsg = store.appendMessage(opts.sid, opts.chatId, { role: 'assistant', text: '' });
    store.resetStream(opts.sid, opts.chatId);
    store.appendStreamEvent(opts.sid, opts.chatId, 'start', { ok: true, assistantMessageId: assistantMsg.id });
    const settings = chat.settings || {};
    void (async () => {
        try {
            await codex.runTurn({
                sessionId: opts.sid,
                chatId: opts.chatId,
                prompt: opts.text,
                config: {
                    cwd: settings.cwd || env.CODEX_CWD,
                    sandbox: settings.sandbox || env.CODEX_SANDBOX,
                    approvalPolicy: settings.approvalPolicy || env.CODEX_APPROVAL_POLICY,
                    model: opts.model || settings.model || env.CODEX_MODEL,
                    reasoningEffort: settings.reasoningEffort || env.CODEX_REASONING_EFFORT
                },
                onEvent: (e) => {
                    if (e.type === 'agent_message') {
                        store.appendToMessageText(opts.sid, opts.chatId, assistantMsg.id, e.message);
                        store.appendStreamEvent(opts.sid, opts.chatId, 'delta', { text: e.message, assistantMessageId: assistantMsg.id });
                        return;
                    }
                    if (e.type === 'approval_request') {
                        store.appendStreamEvent(opts.sid, opts.chatId, 'approval_request', e.request);
                        return;
                    }
                    store.appendStreamEvent(opts.sid, opts.chatId, 'codex_event', e.msg);
                }
            });
            store.appendStreamEvent(opts.sid, opts.chatId, 'done', { ok: true });
        }
        catch (err) {
            const msg = err?.message ? String(err.message) : 'codex_error';
            store.appendStreamEvent(opts.sid, opts.chatId, 'turn_error', { message: msg });
        }
    })();
    return { assistantMessageId: assistantMsg.id };
}
app.post('/api/chats/:chatId/send_async', async (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const parsed = SendSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ ok: false, error: 'bad_request' });
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    try {
        const r = await startChatTurn({ sid, chatId, text: parsed.data.text, model: parsed.data.model });
        res.json({ ok: true, assistantMessageId: r.assistantMessageId });
    }
    catch (e) {
        const msg = String(e?.message || e);
        if (msg === 'chat_busy')
            return res.status(409).json({ ok: false, error: 'chat_busy' });
        if (msg === 'not_found')
            return res.status(404).json({ ok: false, error: 'not_found' });
        res.status(500).json({ ok: false, error: 'start_failed' });
    }
});
// Back-compat: keep `/send` as an SSE stream.
app.post('/api/chats/:chatId/send', async (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const parsed = SendSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ ok: false, error: 'bad_request' });
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    try {
        await startChatTurn({ sid, chatId, text: parsed.data.text, model: parsed.data.model });
    }
    catch (e) {
        const msg = String(e?.message || e);
        if (msg === 'chat_busy')
            return res.status(409).json({ ok: false, error: 'chat_busy' });
        if (msg === 'not_found')
            return res.status(404).json({ ok: false, error: 'not_found' });
        return res.status(500).json({ ok: false, error: 'start_failed' });
    }
    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();
    for (const e of store.listStreamEventsSince(sid, chatId, 0))
        writeSseEvent(res, e);
    const unsub = store.subscribeStream(sid, chatId, (e) => {
        try {
            writeSseEvent(res, e);
            if (e.event === 'done' || e.event === 'turn_error' || e.event === 'error') {
                unsub();
                res.end();
            }
        }
        catch {
            unsub();
        }
    });
    res.on('close', () => {
        unsub();
    });
});
app.post('/api/chats/:chatId/settings', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    const parsed = SettingsSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ ok: false, error: 'bad_request' });
    store.updateChatSettings(sid, chatId, parsed.data);
    res.json({ ok: true });
});
app.post('/api/chats/:chatId/reset', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    codex.reset(sid, chatId);
    res.json({ ok: true });
});
app.post('/api/chats/:chatId/abort', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const chatId = req.params.chatId;
    const chat = store.getChat(sid, chatId);
    if (!chat)
        return res.status(404).json({ ok: false, error: 'not_found' });
    const r = codex.abort(sid, chatId);
    if (!r.ok)
        return res.status(409).json({ ok: false, error: r.error });
    res.json({ ok: true });
});
const ApproveSchema = z.object({
    id: z.string().min(1),
    decision: z.enum(['approved', 'approved_for_session', 'denied', 'abort'])
});
app.post('/api/chats/:chatId/approve', (req, res) => {
    const sid = requireAuth(req, res);
    if (!sid)
        return;
    const parsed = ApproveSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ ok: false, error: 'bad_request' });
    const ok = codex.approve(sid, req.params.chatId, parsed.data.id, parsed.data.decision);
    if (!ok)
        return res.status(404).json({ ok: false, error: 'not_found' });
    res.json({ ok: true });
});
// Serve built web app if present.
const webDist = path.resolve(process.cwd(), '..', 'web', 'dist');
if (fs.existsSync(webDist)) {
    app.use(express.static(webDist));
    app.get('*', (_req, res) => {
        res.sendFile(path.join(webDist, 'index.html'));
    });
}
async function findAvailablePort(host, startPort) {
    for (let p = startPort; p < startPort + 200; p++) {
        const ok = await new Promise((resolve) => {
            const s = net.createServer();
            s.once('error', () => resolve(false));
            s.once('listening', () => s.close(() => resolve(true)));
            s.listen(p, host);
        });
        if (ok)
            return p;
    }
    // Fall back to ephemeral port.
    return await new Promise((resolve, reject) => {
        const s = net.createServer();
        s.once('error', reject);
        s.once('listening', () => {
            const addr = s.address();
            s.close(() => {
                if (addr && typeof addr === 'object')
                    resolve(addr.port);
                else
                    reject(new Error('failed to allocate ephemeral port'));
            });
        });
        s.listen(0, host);
    });
}
const port = await findAvailablePort(env.HOST, env.PORT);
app.listen(port, env.HOST, () => {
    console.log(`[server] listening on http://${env.HOST}:${port}`);
    console.log(`[server] Codex: sandbox=${env.CODEX_SANDBOX} approvalPolicy=${env.CODEX_APPROVAL_POLICY} cwd=${env.CODEX_CWD}`);
    console.log(`[server] Auth mode: ${env.AUTH_MODE}`);
    if (port !== env.PORT) {
        console.log(`[server] Note: requested PORT=${env.PORT} was busy; using PORT=${port}`);
    }
    if (env.HOST === '0.0.0.0') {
        const ifs = os.networkInterfaces();
        const addrs = [];
        for (const entries of Object.values(ifs)) {
            for (const e of entries || []) {
                if (e.family === 'IPv4' && !e.internal) {
                    addrs.push(e.address);
                }
            }
        }
        if (addrs.length) {
            console.log('[server] Accessible on:');
            for (const a of addrs)
                console.log(`  http://${a}:${port}`);
        }
    }
    if (env.AUTH_MODE === 'totp') {
        if (!env.TOTP_SECRET) {
            console.log('[server] TOTP_SECRET is not set; TOTP login will fail.');
        }
        else if (env.PRINT_TOTP_QR && !isTotpProvisioned()) {
            const uri = authenticator.keyuri(env.TOTP_ACCOUNT, env.TOTP_ISSUER, env.TOTP_SECRET);
            console.log('[server] Scan this TOTP QR with your authenticator app:');
            qrcode.generate(uri, { small: true });
        }
        else if (env.PRINT_TOTP_QR && isTotpProvisioned()) {
            console.log(`[server] TOTP already provisioned (marker exists at ${totpProvisionPath}); not printing QR.`);
        }
    }
});
