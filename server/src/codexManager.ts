import {
  CodexMcpClient,
  type CodexApprovalDecision,
  type CodexRunnerEvent,
  type CodexUsage,
  type CodexRateLimits
} from './codexMcpClient.js';

type RunnerState = {
  client: CodexMcpClient;
  busy: boolean;
  abort?: AbortController;
  sessionConfigKey?: string;
};

function sessionConfigKey(config: {
  cwd?: string;
  sandbox?: 'read-only' | 'workspace-write' | 'danger-full-access';
  approvalPolicy?: 'untrusted' | 'on-failure' | 'on-request' | 'never';
  model?: string;
  reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh';
}): string {
  return JSON.stringify({
    cwd: config.cwd ?? null,
    sandbox: config.sandbox ?? null,
    approvalPolicy: config.approvalPolicy ?? null,
    model: config.model ?? null,
    reasoningEffort: config.reasoningEffort ?? null
  });
}

// One runner per (sessionId, chatId). This keeps Codex session continuity for that chat.
export class CodexManager {
  private runners = new Map<string, RunnerState>();

  private key(sessionId: string, chatId: string) {
    return `${sessionId}:${chatId}`;
  }

  get(sessionId: string, chatId: string): RunnerState {
    const k = this.key(sessionId, chatId);
    let r = this.runners.get(k);
    if (!r) {
      r = { client: new CodexMcpClient(), busy: false };
      this.runners.set(k, r);
    }
    return r;
  }

  isBusy(sessionId: string, chatId: string): boolean {
    const r = this.runners.get(this.key(sessionId, chatId));
    return Boolean(r?.busy);
  }

  hasPendingApproval(sessionId: string, chatId: string): boolean {
    const r = this.runners.get(this.key(sessionId, chatId));
    return Boolean(r?.client.hasPendingApprovals());
  }

  approve(sessionId: string, chatId: string, id: string, decision: CodexApprovalDecision): boolean {
    const r = this.runners.get(this.key(sessionId, chatId));
    if (!r) return false;
    return r.client.approve(id, decision);
  }

  abort(sessionId: string, chatId: string): { ok: boolean; error?: string } {
    const r = this.runners.get(this.key(sessionId, chatId));
    if (!r || !r.busy) return { ok: false, error: 'not_running' };
    // If Codex is currently waiting on approval, aborting needs to resolve
    // that wait first; otherwise the turn may remain blocked.
    r.client.abortPendingApprovals();
    r.abort?.abort();
    return { ok: true };
  }

  reset(sessionId: string, chatId: string): { ok: boolean } {
    // Drop runner; a new one will be created on next turn.
    this.runners.delete(this.key(sessionId, chatId));
    return { ok: true };
  }

  async runTurn(opts: {
    sessionId: string;
    chatId: string;
    prompt: string;
    config: {
      cwd?: string;
      sandbox?: 'read-only' | 'workspace-write' | 'danger-full-access';
      approvalPolicy?: 'untrusted' | 'on-failure' | 'on-request' | 'never';
      model?: string;
      reasoningEffort?: 'low' | 'medium' | 'high' | 'xhigh';
    };
    signal?: AbortSignal;
    onEvent: (e: CodexRunnerEvent) => void;
  }): Promise<{ usage?: CodexUsage; rateLimits?: CodexRateLimits }> {
    const r = this.get(opts.sessionId, opts.chatId);
    if (r.busy) throw new Error('chat_busy');
    r.busy = true;
    r.abort = new AbortController();
    const nextConfigKey = sessionConfigKey(opts.config);

    try {
      r.client.setEventHandler(opts.onEvent);

      // Combine abort signals (client disconnect + explicit abort).
      const signal = opts.signal;
      if (signal) {
        if (signal.aborted) r.abort.abort();
        else signal.addEventListener('abort', () => r.abort?.abort(), { once: true });
      }

      // codex-reply does not accept sandbox/approval/cwd/model overrides.
      // When these change, we must restart the underlying Codex session.
      if (r.client.hasSession() && r.sessionConfigKey !== nextConfigKey) {
        r.client.resetSessionState();
      }

      let callResp;
      if (!r.client.hasSession()) {
        callResp = await r.client.startSession(
          {
            prompt: opts.prompt,
            cwd: opts.config.cwd,
            sandbox: opts.config.sandbox,
            'approval-policy': opts.config.approvalPolicy,
            model: opts.config.model,
            config: opts.config.reasoningEffort
              ? { model_reasoning_effort: opts.config.reasoningEffort }
              : undefined
          },
          { signal: r.abort.signal }
        );
        r.sessionConfigKey = nextConfigKey;
      } else {
        callResp = await r.client.continueSession(opts.prompt, { signal: r.abort.signal });
      }

      const usage = callResp ? r.client.getLastUsage() : null;
      const rateLimits = callResp ? r.client.getLastRateLimits() : null;
      return { usage: usage || undefined, rateLimits: rateLimits || undefined };
    } finally {
      r.client.setEventHandler(null);
      r.busy = false;
      r.abort = undefined;
    }
  }

  getChatUsage(sessionId: string, chatId: string): CodexUsage | null {
    const r = this.runners.get(this.key(sessionId, chatId));
    return r?.client.getLastUsage() || null;
  }

  getChatRateLimits(sessionId: string, chatId: string): CodexRateLimits | null {
    const r = this.runners.get(this.key(sessionId, chatId));
    return r?.client.getLastRateLimits() || null;
  }
}
