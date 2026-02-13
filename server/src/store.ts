import { nanoid } from 'nanoid';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type Session = {
  id: string;
  createdAt: number;
  expiresAt: number;
  activeChatId?: string;
};

export type OtpChallenge = {
  id: string;
  createdAt: number;
  expiresAt: number;
  otpHash: string;
  attempts: number;
  lockedUntil?: number;
};

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant' | 'system';
  text: string;
  createdAt: number;
};

export type ChatSettings = {
  model?: string;
  reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh';
  cwd?: string;
  sandbox?: 'read-only' | 'workspace-write' | 'danger-full-access';
  approvalPolicy?: 'untrusted' | 'on-failure' | 'on-request' | 'never';
};

// `null` means "clear this setting" (remove override and fall back to defaults).
export type ChatSettingsPatch = {
  model?: string | null;
  reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh' | null;
  cwd?: string | null;
  sandbox?: 'read-only' | 'workspace-write' | 'danger-full-access' | null;
  approvalPolicy?: 'untrusted' | 'on-failure' | 'on-request' | 'never' | null;
};

export type Chat = {
  id: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessage[];
  settings: ChatSettings;
};

export type StreamEvent = {
  id: number;
  event: string;
  data: any;
  ts: number;
};

type ChatStream = {
  status: 'idle' | 'running' | 'done' | 'error';
  nextId: number;
  events: StreamEvent[];
  listeners: Set<(e: StreamEvent) => void>;
  updatedAt: number;
};

type PersistedStore = {
  version: number;
  savedAt: number;
  sessions: Session[];
  chatsBySession: { [sessionId: string]: Chat[] };
};

export class MemoryStore {
  private sessions = new Map<string, Session>();
  private otpChallenges = new Map<string, OtpChallenge>();
  private chatsBySession = new Map<string, Map<string, Chat>>();
  private streamsByChatKey = new Map<string, ChatStream>();
  private persistTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly persistenceVersion = 1;
  private persistencePath?: string;

  constructor(private opts: {
    sessionTtlMs: number;
    otpTtlMs: number;
    maxOtpAttempts: number;
    otpLockMs: number;
    persistencePath?: string;
  }) {
    this.persistencePath = this.opts.persistencePath?.trim();
    if (this.persistencePath) {
      this.loadFromDisk();
    }
  }

  private now() {
    return Date.now();
  }

  private sha256Hex(s: string): string {
    return crypto.createHash('sha256').update(s).digest('hex');
  }

  private randOtp6(): string {
    // 6 digits with leading zeros.
    const n = crypto.randomInt(0, 1_000_000);
    return String(n).padStart(6, '0');
  }

  private markForPersist() {
    if (!this.persistencePath) return;
    if (this.persistTimer) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null;
      this.persistToDisk();
    }, 250);
  }

  private persistToDisk() {
    if (!this.persistencePath) return;
    try {
      const dir = path.dirname(this.persistencePath);
      if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });

      const data: PersistedStore = {
        version: this.persistenceVersion,
        savedAt: this.now(),
        sessions: Array.from(this.sessions.values()),
        chatsBySession: Object.fromEntries(
          Array.from(this.chatsBySession.entries()).map(([sid, chats]) => [sid, Array.from(chats.values())])
        )
      };

      const tmp = `${this.persistencePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(data));
      fs.renameSync(tmp, this.persistencePath);
    } catch {
      // persistence failure should not block runtime
    }
  }

  private isSessionLike(v: unknown): v is Session {
    return (
      typeof v === 'object' &&
      v !== null &&
      typeof (v as Session).id === 'string' &&
      typeof (v as Session).createdAt === 'number' &&
      typeof (v as Session).expiresAt === 'number' &&
      (!(v as Session).activeChatId || typeof (v as Session).activeChatId === 'string')
    );
  }

  private isChatLike(v: unknown): v is Chat {
    return (
      typeof v === 'object' &&
      v !== null &&
      typeof (v as Chat).id === 'string' &&
      typeof (v as Chat).createdAt === 'number' &&
      typeof (v as Chat).updatedAt === 'number' &&
      Array.isArray((v as Chat).messages) &&
      typeof (v as Chat).settings === 'object' &&
      (v as Chat).settings !== null
    );
  }

  private loadFromDisk() {
    if (!this.persistencePath) return;
    try {
      const raw = fs.readFileSync(this.persistencePath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedStore>;
      if (!parsed || typeof parsed !== 'object') return;

      const now = this.now();
      const sessions = Array.isArray(parsed.sessions) ? parsed.sessions : [];
      for (const s of sessions) {
        if (!this.isSessionLike(s)) continue;
        if (s.expiresAt <= now) continue;
        this.sessions.set(s.id, s);
      }

      const rawChats = parsed.chatsBySession;
      if (rawChats && typeof rawChats === 'object') {
        for (const [sid, chatsValue] of Object.entries(rawChats)) {
          if (!Array.isArray(chatsValue) || !this.sessions.has(sid)) continue;
          const m = new Map<string, Chat>();
          for (const chatValue of chatsValue) {
            if (!this.isChatLike(chatValue)) continue;
            const safeMessages = Array.isArray(chatValue.messages)
              ? chatValue.messages.filter(
                  (msg): msg is ChatMessage =>
                    typeof msg === 'object' &&
                    msg !== null &&
                    typeof (msg as ChatMessage).id === 'string' &&
                    (['user', 'assistant', 'system'] as const).includes((msg as ChatMessage).role as any) &&
                    typeof (msg as ChatMessage).text === 'string' &&
                    typeof (msg as ChatMessage).createdAt === 'number'
                )
              : [];

            const safeSettings = {
              model: typeof chatValue.settings?.model === 'string' ? chatValue.settings.model : undefined,
              reasoningEffort:
                chatValue.settings?.reasoningEffort === 'low' ||
                chatValue.settings?.reasoningEffort === 'medium' ||
                chatValue.settings?.reasoningEffort === 'high' ||
                chatValue.settings?.reasoningEffort === 'xhigh'
                  ? chatValue.settings?.reasoningEffort
                  : undefined,
              cwd: typeof chatValue.settings?.cwd === 'string' ? chatValue.settings.cwd : undefined,
              sandbox:
                chatValue.settings?.sandbox === 'read-only' ||
                chatValue.settings?.sandbox === 'workspace-write' ||
                chatValue.settings?.sandbox === 'danger-full-access'
                  ? chatValue.settings.sandbox
                  : undefined,
              approvalPolicy:
                chatValue.settings?.approvalPolicy === 'untrusted' ||
                chatValue.settings?.approvalPolicy === 'on-failure' ||
                chatValue.settings?.approvalPolicy === 'on-request' ||
                chatValue.settings?.approvalPolicy === 'never'
                  ? chatValue.settings.approvalPolicy
                  : undefined
            };

            const chat: Chat = {
              id: chatValue.id,
              createdAt: chatValue.createdAt,
              updatedAt: chatValue.updatedAt,
              messages: safeMessages,
              settings: safeSettings
            };

            m.set(chat.id, chat);
          }

          if (m.size > 0) {
            this.chatsBySession.set(sid, m);
          }
        }
      }
    } catch {
      // ignore bad/old/missing persistence file
    }
  }

  sweep() {
    const t = this.now();
    let changed = false;

    for (const [id, sess] of this.sessions) {
      if (sess.expiresAt <= t) {
        this.sessions.delete(id);
        changed = true;
      }
    }

    for (const [id, ch] of this.otpChallenges) {
      if (ch.expiresAt <= t) this.otpChallenges.delete(id);
    }

    for (const [sid, chats] of this.chatsBySession) {
      if (!this.sessions.has(sid)) {
        this.chatsBySession.delete(sid);
        changed = true;
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
        changed = true;
        continue;
      }
      if (s.status !== 'running' && s.updatedAt + streamTtlMs <= t) {
        this.streamsByChatKey.delete(k);
        changed = true;
      }
    }

    if (changed) this.markForPersist();
  }

  createSession(): Session {
    const createdAt = this.now();
    const id = nanoid(24);
    const session: Session = {
      id,
      createdAt,
      expiresAt: createdAt + this.opts.sessionTtlMs,
      activeChatId: undefined
    };
    this.sessions.set(id, session);
    this.markForPersist();
    return session;
  }

  // Use a stable id to make multiple devices share the same logical session (e.g. TOTP account).
  getOrCreateSessionWithId(id: string): Session {
    const now = this.now();
    const existing = this.sessions.get(id);
    if (existing && existing.expiresAt > now) {
      existing.expiresAt = now + this.opts.sessionTtlMs;
      this.sessions.set(id, existing);
      this.markForPersist();
      return existing;
    }

    const session: Session = {
      id,
      createdAt: now,
      expiresAt: now + this.opts.sessionTtlMs,
      activeChatId: undefined
    };
    this.sessions.set(id, session);
    this.markForPersist();
    return session;
  }

  getSession(id: string): Session | null {
    const s = this.sessions.get(id);
    if (!s) return null;
    if (s.expiresAt <= this.now()) {
      this.sessions.delete(id);
      this.chatsBySession.delete(id);
      this.markForPersist();
      return null;
    }
    return s;
  }

  getAllSessions(): Session[] {
    const all: Session[] = Array.from(this.sessions.values())
      .filter((s) => s.expiresAt > this.now())
      .map((s) => ({
        id: s.id,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        activeChatId: s.activeChatId
      }));
    const invalid = Array.from(this.sessions.keys()).filter((id) => !all.some((s) => s.id === id));
    if (invalid.length) {
      for (const id of invalid) {
        this.sessions.delete(id);
        this.chatsBySession.delete(id);
      }
      this.markForPersist();
    }
    return all;
  }

  refreshSession(id: string): Session | null {
    const s = this.getSession(id);
    if (!s) return null;
    s.expiresAt = this.now() + this.opts.sessionTtlMs;
    this.sessions.set(id, s);
    this.markForPersist();
    return s;
  }

  getActiveChatId(sessionId: string): string | null {
    const s = this.getSession(sessionId);
    if (!s?.activeChatId) return null;
    const m = this.getChatsMapForSession(sessionId);
    if (!m.has(s.activeChatId)) {
      s.activeChatId = undefined;
      this.sessions.set(sessionId, s);
      this.markForPersist();
      return null;
    }
    return s.activeChatId;
  }

  setActiveChatId(sessionId: string, chatId: string): boolean {
    const s = this.getSession(sessionId);
    if (!s) return false;
    const m = this.getChatsMapForSession(sessionId);
    if (!m.has(chatId)) return false;
    s.activeChatId = chatId;
    this.sessions.set(sessionId, s);
    this.markForPersist();
    return true;
  }

  createOtpChallenge(): { challenge: OtpChallenge; otp: string } {
    const createdAt = this.now();
    const otp = this.randOtp6();
    const id = nanoid(18);
    const challenge: OtpChallenge = {
      id,
      createdAt,
      expiresAt: createdAt + this.opts.otpTtlMs,
      otpHash: this.sha256Hex(otp),
      attempts: 0
    };
    this.otpChallenges.set(id, challenge);
    return { challenge, otp };
  }

  verifyOtpChallenge(challengeId: string, otp: string): { ok: boolean; error?: string } {
    const ch = this.otpChallenges.get(challengeId);
    if (!ch) return { ok: false, error: 'not_found' };

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

  private getChatsMapForSession(sessionId: string): Map<string, Chat> {
    let m = this.chatsBySession.get(sessionId);
    if (!m) {
      m = new Map();
      this.chatsBySession.set(sessionId, m);
    }
    return m;
  }

  private chatKey(sessionId: string, chatId: string): string {
    return `${sessionId}:${chatId}`;
  }

  private ensureStream(sessionId: string, chatId: string): ChatStream {
    const key = this.chatKey(sessionId, chatId);
    let s = this.streamsByChatKey.get(key);
    if (!s) {
      s = { status: 'idle', nextId: 1, events: [], listeners: new Set(), updatedAt: this.now() };
      this.streamsByChatKey.set(key, s);
    }
    return s;
  }

  resetStream(sessionId: string, chatId: string): void {
    const s = this.ensureStream(sessionId, chatId);
    s.status = 'running';
    s.events = [];
    s.nextId = 1;
    s.updatedAt = this.now();
    // keep listeners
    this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
  }

  getStreamRuntime(sessionId: string, chatId: string): { status: ChatStream['status']; lastEventId: number; updatedAt: number } {
    const s = this.ensureStream(sessionId, chatId);
    const lastEventId = Math.max(0, s.nextId - 1);
    return { status: s.status, lastEventId, updatedAt: s.updatedAt };
  }

  appendStreamEvent(sessionId: string, chatId: string, event: string, data: any): StreamEvent {
    const s = this.ensureStream(sessionId, chatId);
    const e: StreamEvent = { id: s.nextId++, event, data, ts: this.now() };
    s.events.push(e);
    if (event === 'done') s.status = 'done';
    // Keep backward-compat for older event name "error".
    if (event === 'turn_error' || event === 'error') s.status = 'error';
    s.updatedAt = this.now();

    // Bound memory. If client falls behind, it can always fall back to GET /api/chats/:id.
    const maxEvents = 2000;
    if (s.events.length > maxEvents) {
      s.events.splice(0, s.events.length - maxEvents);
    }

    // Notify subscribers.
    for (const fn of s.listeners) fn(e);
    this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
    return e;
  }

  listStreamEventsSince(sessionId: string, chatId: string, afterId: number): StreamEvent[] {
    const s = this.ensureStream(sessionId, chatId);
    return s.events.filter((e) => e.id > afterId);
  }

  subscribeStream(sessionId: string, chatId: string, fn: (e: StreamEvent) => void): () => void {
    const s = this.ensureStream(sessionId, chatId);
    s.listeners.add(fn);
    this.streamsByChatKey.set(this.chatKey(sessionId, chatId), s);
    return () => {
      const cur = this.streamsByChatKey.get(this.chatKey(sessionId, chatId));
      if (!cur) return;
      cur.listeners.delete(fn);
      this.streamsByChatKey.set(this.chatKey(sessionId, chatId), cur);
    };
  }

  createChat(sessionId: string): Chat {
    const id = nanoid(14);
    const now = this.now();
    const chat: Chat = { id, createdAt: now, updatedAt: now, messages: [], settings: {} };
    const m = this.getChatsMapForSession(sessionId);
    m.set(id, chat);
    const s = this.getSession(sessionId);
    if (s) {
      s.activeChatId = id;
      this.sessions.set(sessionId, s);
    }
    this.markForPersist();
    return chat;
  }

  listChats(sessionId: string): { id: string; updatedAt: number; createdAt: number; preview?: string }[] {
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

  deleteChat(sessionId: string, chatId: string): boolean {
    const m = this.chatsBySession.get(sessionId);
    if (!m || !m.has(chatId)) return false;

    const removed = m.delete(chatId);
    if (removed && m.size === 0) {
      this.chatsBySession.delete(sessionId);
    }

    if (removed) {
      const s = this.sessions.get(sessionId);
      if (s && s.activeChatId === chatId) {
        s.activeChatId = undefined;
        this.sessions.set(sessionId, s);
      }
      this.streamsByChatKey.delete(this.chatKey(sessionId, chatId));
      this.markForPersist();
    }

    return removed;
  }

  getChat(sessionId: string, chatId: string): Chat | null {
    const m = this.getChatsMapForSession(sessionId);
    return m.get(chatId) || null;
  }

  updateChatSettings(sessionId: string, chatId: string, patch: ChatSettingsPatch): ChatSettings {
    const chat = this.getChat(sessionId, chatId);
    if (!chat) throw new Error('chat_not_found');
    const next: ChatSettings = { ...chat.settings };
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) {
        delete (next as any)[k];
      } else if (typeof v !== 'undefined') {
        (next as any)[k] = v;
      }
    }
    chat.settings = next;
    chat.updatedAt = this.now();
    this.markForPersist();
    return chat.settings;
  }

  appendMessage(sessionId: string, chatId: string, msg: Omit<ChatMessage, 'id' | 'createdAt'> & { id?: string; createdAt?: number }): ChatMessage {
    const chat = this.getChat(sessionId, chatId);
    if (!chat) throw new Error('chat_not_found');
    const full: ChatMessage = {
      id: msg.id ?? nanoid(12),
      role: msg.role,
      text: msg.text,
      createdAt: msg.createdAt ?? this.now()
    };
    chat.messages.push(full);
    chat.updatedAt = this.now();
    this.markForPersist();
    return full;
  }

  appendToMessageText(sessionId: string, chatId: string, messageId: string, delta: string): void {
    const chat = this.getChat(sessionId, chatId);
    if (!chat) throw new Error('chat_not_found');
    const idx = chat.messages.findIndex((m) => m.id === messageId);
    if (idx === -1) throw new Error('message_not_found');
    chat.messages[idx] = { ...chat.messages[idx], text: chat.messages[idx].text + delta };
    chat.updatedAt = this.now();
    this.markForPersist();
  }

  setMessageText(sessionId: string, chatId: string, messageId: string, text: string): void {
    const chat = this.getChat(sessionId, chatId);
    if (!chat) throw new Error('chat_not_found');
    const idx = chat.messages.findIndex((m) => m.id === messageId);
    if (idx === -1) throw new Error('message_not_found');
    chat.messages[idx] = { ...chat.messages[idx], text };
    chat.updatedAt = this.now();
    this.markForPersist();
  }
}
