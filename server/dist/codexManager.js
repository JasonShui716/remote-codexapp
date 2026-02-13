import { CodexMcpClient } from './codexMcpClient.js';
// One runner per (sessionId, chatId). This keeps Codex session continuity for that chat.
export class CodexManager {
    runners = new Map();
    key(sessionId, chatId) {
        return `${sessionId}:${chatId}`;
    }
    get(sessionId, chatId) {
        const k = this.key(sessionId, chatId);
        let r = this.runners.get(k);
        if (!r) {
            r = { client: new CodexMcpClient(), busy: false };
            this.runners.set(k, r);
        }
        return r;
    }
    isBusy(sessionId, chatId) {
        const r = this.runners.get(this.key(sessionId, chatId));
        return Boolean(r?.busy);
    }
    hasPendingApproval(sessionId, chatId) {
        const r = this.runners.get(this.key(sessionId, chatId));
        return Boolean(r?.client.hasPendingApprovals());
    }
    approve(sessionId, chatId, id, decision) {
        const r = this.runners.get(this.key(sessionId, chatId));
        if (!r)
            return false;
        return r.client.approve(id, decision);
    }
    abort(sessionId, chatId) {
        const r = this.runners.get(this.key(sessionId, chatId));
        if (!r || !r.abort)
            return { ok: false, error: 'not_running' };
        r.abort.abort();
        return { ok: true };
    }
    reset(sessionId, chatId) {
        // Drop runner; a new one will be created on next turn.
        this.runners.delete(this.key(sessionId, chatId));
        return { ok: true };
    }
    async runTurn(opts) {
        const r = this.get(opts.sessionId, opts.chatId);
        if (r.busy)
            throw new Error('chat_busy');
        r.busy = true;
        r.abort = new AbortController();
        try {
            r.client.setEventHandler(opts.onEvent);
            // Combine abort signals (client disconnect + explicit abort).
            const signal = opts.signal;
            if (signal) {
                if (signal.aborted)
                    r.abort.abort();
                else
                    signal.addEventListener('abort', () => r.abort?.abort(), { once: true });
            }
            if (!r.client.hasSession()) {
                await r.client.startSession({
                    prompt: opts.prompt,
                    cwd: opts.config.cwd,
                    sandbox: opts.config.sandbox,
                    'approval-policy': opts.config.approvalPolicy,
                    model: opts.config.model,
                    config: opts.config.reasoningEffort
                        ? { model_reasoning_effort: opts.config.reasoningEffort }
                        : undefined
                }, { signal: r.abort.signal });
            }
            else {
                await r.client.continueSession(opts.prompt, { signal: r.abort.signal });
            }
        }
        finally {
            r.client.setEventHandler(null);
            r.busy = false;
            r.abort = undefined;
        }
    }
}
