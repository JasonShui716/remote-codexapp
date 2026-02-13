import { z } from 'zod';
function emptyToUndefined(v) {
    if (typeof v !== 'string')
        return v;
    const t = v.trim();
    return t === '' ? undefined : v;
}
const EnvSchema = z.object({
    HOST: z.string().default('127.0.0.1'),
    PORT: z.coerce.number().int().positive().default(18888),
    SESSION_TTL_MS: z.coerce.number().int().positive().default(60 * 60 * 1000),
    OTP_TTL_MS: z.coerce.number().int().positive().default(10 * 60 * 1000),
    STUCK_RUNNING_ABORT_MS: z.coerce.number().int().positive().default(45 * 1000),
    // In production, set this so session cookies can't be forged if you ever
    // switch to stateless cookies.
    SESSION_SECRET: z.string().min(16).default('dev-only-change-me-please'),
    // Codex CLI needs OpenAI credentials in environment, typically OPENAI_API_KEY.
    // We don't read it here; Codex reads it directly.
    CODEX_MODEL: z.preprocess(emptyToUndefined, z.string().optional()),
    CODEX_REASONING_EFFORT: z.preprocess(emptyToUndefined, z.enum(['low', 'medium', 'high', 'xhigh']).optional()),
    CODEX_CWD: z.string().default(process.cwd()),
    // Allowed roots for the web UI directory picker (comma-separated absolute paths).
    // If unset, defaults to CODEX_CWD.
    CWD_ROOTS: z.preprocess(emptyToUndefined, z.string().optional()),
    CODEX_SANDBOX: z.enum(['read-only', 'workspace-write', 'danger-full-access']).default('workspace-write'),
    CODEX_APPROVAL_POLICY: z.enum(['untrusted', 'on-failure', 'on-request', 'never']).default('untrusted'),
    // Auth mode:
    // - otp: request OTP and read from server console logs (current default)
    // - totp: scan once in an authenticator app, then enter 6-digit code
    AUTH_MODE: z.enum(['otp', 'totp']).default('otp'),
    TOTP_SECRET: z.preprocess(emptyToUndefined, z.string().optional()), // base32
    TOTP_ISSUER: z.string().default('Codex Remoteapp'),
    TOTP_ACCOUNT: z.string().default('codex'),
    PRINT_TOTP_QR: z.coerce.boolean().default(false),
    EXPOSE_TOTP_URI: z.coerce.boolean().default(false),
    // Relative paths are resolved relative to the server process cwd (typically `server/`).
    // If this file exists, TOTP provisioning is considered "done" and QR/URI will no longer be served/printed.
    TOTP_PROVISION_FILE: z.string().default('.totp_provisioned'),
    // Dev: allow frontend origin.
    WEB_ORIGIN: z.preprocess(emptyToUndefined, z.string().optional())
});
export function readEnv() {
    const parsed = EnvSchema.safeParse(process.env);
    if (!parsed.success) {
        // Keep this readable.
        const msg = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n');
        throw new Error(`Invalid env:\n${msg}`);
    }
    return parsed.data;
}
