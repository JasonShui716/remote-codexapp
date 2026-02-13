import { nanoid } from 'nanoid';
import crypto from 'node:crypto';
export class MemoryStore {
    opts;
    sessions = new Map();
    otpChallenges = new Map();
    chatsBySession = new Map();
    streamsByChatKey = new Map();
    constructor(opts) {
        this.opts = opts;
    }
    now() {
        return Date.now();
    }
    sha256Hex(s) {
        return crypto.createHash('sha256').update(s).digest('hex');
    }
    randOtp6() {
        // 6 digits with leading zeros.
        const n = crypto.randomInt(0, 1_000_000);
        return String(n).padStart(6, '0');
    }
    sweep() {
        const t = this.now();
        for (const [id, sess] of this.sessions) {
            if (sess.expiresAt <= t)
                this.sessions.delete(id);
        }
        for (const [id, ch] of this.otpChallenges) {
            if (ch.expiresAt <= t)
                this.otpChallenges.delete(id);
        }
        for (const [sid, chats] of this.chatsBySession) {
            if (!this.sessions.has(sid)) {
                this.chatsBySession.delete(sid);
                continue;
            }
            // no-op; keep chats while session lives
            void chats;
        }
        // Drop old/finished streams and any streams for expired sessions.
        const streamTtlMs = 15 * 60 * 1000;
        for (const [k, s] of this.streamsByChatKey) {
            const sid = k.split(':', 1)[0] || '';
            if (!this.sessions.has(sid)) {
                this.streamsByChatKey.delete(k);
                continue;
            }
            if (s.status !== 'running' && s.updatedAt + streamTtlMs <= t) {
                this.streamsByChatKey.delete(k);
            }
        }
    }
    createSession() {
        const createdAt = this.now();
        const id = nanoid(24);
        const session = {
            id,
            createdAt,
            expiresAt: createdAt + this.opts.sessionTtlMs,
            activeChatId: undefined
        };
        this.sessions.set(id, session);
        return session;
    }
    // Use a stable id to make multiple devices share the same logical session (e.g. TOTP account).
    getOrCreateSessionWithId(id) {
        const now = this.now();
        const existing = this.sessions.get(id);
        if (existing && existing.expiresAt > now) {
            existing.expiresAt = now + this.opts.sessionTtlMs;
            this.sessions.set(id, existing);
            return existing;
        }
        const session = {
            id,
            createdAt: now,
            expiresAt: now + this.opts.sessionTtlMs,
            activeChatId: undefined
        };
        this.sessions.set(id, session);
        return session;
    }
    getSession(id) {
        const s = this.sessions.get(id);
        if (!s)
            return null;
        if (s.expiresAt <= this.now()) {
            this.sessions.delete(id);
            return null;
        }
        return s;
    }
    refreshSession(id) {
        const s = this.getSession(id);
        if (!s)
            return null;
        s.expiresAt = this.now() + this.opts.sessionTtlMs;
        this.sessions.set(id, s);
        return s;
    }
    getActiveChatId(sessionId) {
        const s = this.getSession(sessionId);
        if (!s?.activeChatId)
            return null;
        const m = this.getChatsMapForSession(sessionId);
        if (!m.has(s.activeChatId)) {
            s.activeChatId = undefined;
            this.sessions.set(sessionId, s);
            return null;
        }
        return s.activeChatId;
    }
    setActiveChatId(sessionId, chatId) {
        const s = this.getSession(sessionId);
        if (!s)
            return false;
        const m = this.getChatsMapForSession(sessionId);
        if (!m.has(chatId))
            return false;
        s.activeChatId = chatId;
        this.sessions.set(sessionId, s);
        return true;
    }
    createOtpChallenge() {
        const createdAt = this.now();
        const otp = this.randOtp6();
        const id = nanoid(18);
        const challenge = {
            id,
            createdAt,
            expiresAt: createdAt + this.opts.otpTtlMs,
            otpHash: this.sha256Hex(otp),
            attempts: 0
        };
        this.otpChallenges.set(id, challenge);
        return { challenge, otp };
    }
    verifyOtpChallenge(challengeId, otp) {
        const ch = this.otpChallenges.get(challengeId);
        if (!ch)
            return { ok: false, error: 'not_found' };
        const t = this.now();
        if (ch.expiresAt <= t) {
            this.otpChallenges.delete(challengeId);
            return { ok: false, error: 'expired' };
        }
        if (ch.lockedUntil && ch.lockedUntil > t) {
            return { ok: false, error: 'locked' };
        }
        ch.attempts += 1;
        const ok = this.sha256Hex(otp) === ch.otpHash;
        if (ok) {
            this.otpChallenges.delete(challengeId);
            return { ok: true };
        }
        if (ch.attempts >= this.opts.maxOtpAttempts) {
            ch.lockedUntil = t + this.opts.otpLockMs;
        }
        this.otpChallenges.set(challengeId, ch);
        return { ok: false, error: 'invalid' };
    }
    getChatsMapForSession(sessionId) {
        let m = this.chatsBySession.get(sessionId);
        if (!m) {
            m = new Map();
            this.chatsBySession.set(sessionId, m);
        }
        return m;
    }
    chatKey(sessionId, chatId) {
        return `${sessionId}:${chatId}`;
    }
    ensureStream(sessionId, chatId) {
        const key = this.chatKey(sessionId, chatId);
        let s = this.streamsByChatKey.get(key);
        if (!s) {
            s = { status: 'idle', nextId: 1, events: [], listeners: new Set(), updatedAt: this.now() };
            this.streamsByChatKey.set(key, s);
        }
        return s;
    }
    resetStream(sessionId, chatId) {
        const s = this.ensureStream(sessionId, chatId);
        s.status = 'running';
        s.events = [];
        s.nextId = 1;
        s.updatedAt = this.now();
        // keep listeners
        this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
    }
    getStreamRuntime(sessionId, chatId) {
        const s = this.ensureStream(sessionId, chatId);
        const lastEventId = Math.max(0, s.nextId - 1);
        return { status: s.status, lastEventId, updatedAt: s.updatedAt };
    }
    appendStreamEvent(sessionId, chatId, event, data) {
        const s = this.ensureStream(sessionId, chatId);
        const e = { id: s.nextId++, event, data, ts: this.now() };
        s.events.push(e);
        if (event === 'done')
            s.status = 'done';
        // Keep backward-compat for older event name "error".
        if (event === 'turn_error' || event === 'error')
            s.status = 'error';
        s.updatedAt = this.now();
        // Bound memory. If client falls behind, it can always fall back to GET /api/chats/:id.
        const maxEvents = 2000;
        if (s.events.length > maxEvents) {
            s.events.splice(0, s.events.length - maxEvents);
        }
        // Notify subscribers.
        for (const fn of s.listeners)
            fn(e);
        this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
        return e;
    }
    listStreamEventsSince(sessionId, chatId, afterId) {
        const s = this.ensureStream(sessionId, chatId);
        return s.events.filter((e) => e.id > afterId);
    }
    subscribeStream(sessionId, chatId, fn) {
        const s = this.ensureStream(sessionId, chatId);
        s.listeners.add(fn);
        this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
        return () => {
            const cur = this.streamsByChatKey.get(this.chatKey(sessionId, chatId));
            if (!cur)
                return;
            cur.listeners.delete(fn);
            this.streamsByChatKey.set(this.chatKey(sessionId, chatId), cur);
        };
    }
    createChat(sessionId) {
        const id = nanoid(14);
        const now = this.now();
        const chat = { id, createdAt: now, updatedAt: now, messages: [], settings: {} };
        const m = this.getChatsMapForSession(sessionId);
        m.set(id, chat);
        const s = this.getSession(sessionId);
        if (s) {
            s.activeChatId = id;
            this.sessions.set(sessionId, s);
        }
        return chat;
    }
    listChats(sessionId) {
        const m = this.getChatsMapForSession(sessionId);
        const arr = Array.from(m.values()).map((c) => ({
            id: c.id,
            createdAt: c.createdAt,
            updatedAt: c.updatedAt,
            preview: c.messages.slice(-1)[0]?.text
        }));
        arr.sort((a, b) => b.updatedAt - a.updatedAt);
        return arr;
    }
    getChat(sessionId, chatId) {
        const m = this.getChatsMapForSession(sessionId);
        return m.get(chatId) || null;
    }
    updateChatSettings(sessionId, chatId, patch) {
        const chat = this.getChat(sessionId, chatId);
        if (!chat)
            throw new Error('chat_not_found');
        const next = { ...chat.settings };
        for (const [k, v] of Object.entries(patch)) {
            if (v === null) {
                delete next[k];
            }
            else if (typeof v !== 'undefined') {
                next[k] = v;
            }
        }
        chat.settings = next;
        chat.updatedAt = this.now();
        return chat.settings;
    }
    appendMessage(sessionId, chatId, msg) {
        const chat = this.getChat(sessionId, chatId);
        if (!chat)
            throw new Error('chat_not_found');
        const full = {
            id: msg.id ?? nanoid(12),
            role: msg.role,
            text: msg.text,
            createdAt: msg.createdAt ?? this.now()
        };
        chat.messages.push(full);
        chat.updatedAt = this.now();
        return full;
    }
    appendToMessageText(sessionId, chatId, messageId, delta) {
        const chat = this.getChat(sessionId, chatId);
        if (!chat)
            throw new Error('chat_not_found');
        const idx = chat.messages.findIndex((m) => m.id === messageId);
        if (idx === -1)
            throw new Error('message_not_found');
        chat.messages[idx] = { ...chat.messages[idx], text: chat.messages[idx].text + delta };
        chat.updatedAt = this.now();
    }
}
