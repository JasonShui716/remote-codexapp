import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
function isObj(v) {
    return typeof v === 'object' && v !== null;
}
export class CodexMcpClient {
    client;
    transport = null;
    connected = false;
    sessionId = null;
    conversationId = null;
    onEvent = null;
    pendingApprovals = new Map();
    sawAssistantTextInFlight = false;
    constructor() {
        this.client = new Client({ name: 'codex-remoteapp', version: '1.0.0' }, { capabilities: { elicitation: {} } });
        // Codex emits notifications with method "codex/event".
        this.client.setNotificationHandler(z
            .object({
            method: z.literal('codex/event'),
            params: z.object({ msg: z.any() }).passthrough()
        })
            .passthrough(), (data) => {
            const msg = data.params?.msg;
            this.updateIdentifiersFromEvent(msg);
            // Stream assistant text exactly once.
            // Codex typically emits both:
            // - agent_message_delta (primary)
            // - agent_message_content_delta (duplicate)
            // Plus sometimes a final full message. We avoid double-appending.
            if (isObj(msg) && msg.type === 'agent_message_delta' && typeof msg.delta === 'string') {
                this.onEvent?.({ type: 'agent_message', message: msg.delta });
                this.sawAssistantTextInFlight = true;
                return;
            }
            if (isObj(msg) && msg.type === 'agent_message_content_delta' && typeof msg.delta === 'string') {
                // Ignore (duplicates agent_message_delta).
                return;
            }
            if (isObj(msg) &&
                msg.type === 'agent_message' &&
                typeof msg.message === 'string' &&
                !this.sawAssistantTextInFlight) {
                this.onEvent?.({ type: 'agent_message', message: msg.message });
                this.sawAssistantTextInFlight = true;
                return;
            }
            if (isObj(msg) &&
                msg.type === 'raw_response_item' &&
                !this.sawAssistantTextInFlight &&
                isObj(msg.item) &&
                msg.item.role === 'assistant' &&
                Array.isArray(msg.item.content)) {
                for (const c of msg.item.content) {
                    if (isObj(c) && c.type === 'output_text' && typeof c.text === 'string' && c.text.length) {
                        this.onEvent?.({ type: 'agent_message', message: c.text });
                        this.sawAssistantTextInFlight = true;
                        return;
                    }
                }
            }
            this.onEvent?.({ type: 'raw', msg });
        });
    }
    setEventHandler(handler) {
        this.onEvent = handler;
    }
    async connect() {
        if (this.connected)
            return;
        this.transport = new StdioClientTransport({
            command: 'codex',
            args: ['mcp-server'],
            env: Object.keys(process.env).reduce((acc, k) => {
                const v = process.env[k];
                if (typeof v === 'string')
                    acc[k] = v;
                return acc;
            }, {})
        });
        // Permission requests come via MCP elicitation.
        this.client.setRequestHandler(ElicitRequestSchema, async (request) => {
            const p = request.params;
            const approvalId = String(p?.codex_call_id || p?.codex_mcp_tool_call_id || p?.codex_event_id || '');
            const id = approvalId || String(Date.now());
            const req = {
                id,
                message: typeof p?.message === 'string' ? p.message : undefined,
                command: Array.isArray(p?.codex_command) ? p.codex_command.map(String) : undefined,
                cwd: typeof p?.codex_cwd === 'string' ? p.codex_cwd : undefined
            };
            const decision = await new Promise((resolve) => {
                this.pendingApprovals.set(id, resolve);
                this.onEvent?.({ type: 'approval_request', request: req });
            });
            this.pendingApprovals.delete(id);
            return { decision };
        });
        await this.client.connect(this.transport);
        this.connected = true;
    }
    hasSession() {
        return this.sessionId !== null;
    }
    hasPendingApprovals() {
        return this.pendingApprovals.size > 0;
    }
    approve(id, decision) {
        const resolver = this.pendingApprovals.get(id);
        if (!resolver)
            return false;
        resolver(decision);
        return true;
    }
    async startSession(config, opts) {
        await this.connect();
        this.sawAssistantTextInFlight = false;
        const resp = await this.client.callTool({ name: 'codex', arguments: config }, undefined, { signal: opts?.signal, timeout: 7 * 24 * 60 * 60 * 1000 });
        this.extractIdentifiers(resp);
        return resp;
    }
    async continueSession(prompt, opts) {
        await this.connect();
        if (!this.sessionId)
            throw new Error('missing sessionId');
        if (!this.conversationId)
            this.conversationId = this.sessionId;
        this.sawAssistantTextInFlight = false;
        const resp = await this.client.callTool({ name: 'codex-reply', arguments: { sessionId: this.sessionId, conversationId: this.conversationId, prompt } }, undefined, { signal: opts?.signal, timeout: 7 * 24 * 60 * 60 * 1000 });
        this.extractIdentifiers(resp);
        return resp;
    }
    updateIdentifiersFromEvent(event) {
        if (!isObj(event))
            return;
        const cand = [event, isObj(event.data) ? event.data : null].filter(Boolean);
        for (const c of cand) {
            const sid = c.session_id ?? c.sessionId;
            if (sid)
                this.sessionId = String(sid);
            const cid = c.conversation_id ?? c.conversationId;
            if (cid)
                this.conversationId = String(cid);
        }
    }
    extractIdentifiers(resp) {
        const meta = resp?.meta || {};
        if (meta.sessionId)
            this.sessionId = String(meta.sessionId);
        if (meta.conversationId)
            this.conversationId = String(meta.conversationId);
        const content = resp?.content;
        if (Array.isArray(content)) {
            for (const item of content) {
                if (!this.sessionId && item?.sessionId)
                    this.sessionId = String(item.sessionId);
                if (!this.conversationId && item?.conversationId)
                    this.conversationId = String(item.conversationId);
            }
        }
    }
}
