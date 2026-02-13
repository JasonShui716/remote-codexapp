import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import net from 'node:net';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { authenticator } from 'otplib';
import WebSocket from 'ws';

type StartedServer = {
  baseUrl: string;
  proc: ChildProcessWithoutNullStreams;
  tmpDir: string;
};

async function findFreePort(host = '127.0.0.1'): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.once('listening', () => {
      const addr = server.address();
      server.close(() => {
        if (!addr || typeof addr !== 'object') {
          reject(new Error('failed_to_allocate_port'));
          return;
        }
        resolve(addr.port);
      });
    });
    server.listen(0, host);
  });
}

async function waitForServerReady(
  proc: ChildProcessWithoutNullStreams,
  timeoutMs: number
): Promise<string> {
  const startedAt = Date.now();
  let stdoutBuf = '';
  let stderrBuf = '';

  return await new Promise<string>((resolve, reject) => {
    const onStdout = (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      stdoutBuf += text;
      const match = stdoutBuf.match(/\[server\] listening on (http:\/\/[^\s]+)/);
      if (match?.[1]) {
        cleanup();
        resolve(match[1]);
      }
    };
    const onStderr = (chunk: Buffer) => {
      stderrBuf += chunk.toString('utf8');
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(
        new Error(
          `server_exited_before_ready code=${code} signal=${signal}\nstdout:\n${stdoutBuf}\nstderr:\n${stderrBuf}`
        )
      );
    };
    const timer = setInterval(() => {
      if (Date.now() - startedAt < timeoutMs) return;
      cleanup();
      reject(new Error(`server_ready_timeout\nstdout:\n${stdoutBuf}\nstderr:\n${stderrBuf}`));
    }, 50);

    const cleanup = () => {
      clearInterval(timer);
      proc.stdout.off('data', onStdout);
      proc.stderr.off('data', onStderr);
      proc.off('exit', onExit);
    };

    proc.stdout.on('data', onStdout);
    proc.stderr.on('data', onStderr);
    proc.on('exit', onExit);
  });
}

async function startServerForTest(): Promise<StartedServer> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'codex-remoteapp-test-'));
  const workspaceDir = path.join(tmpDir, 'workspace');
  const dataDir = path.join(tmpDir, 'data');
  await fs.mkdir(workspaceDir, { recursive: true });
  await fs.mkdir(dataDir, { recursive: true });

  const port = await findFreePort('127.0.0.1');
  const proc = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts'], {
    cwd: path.resolve(process.cwd()),
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(port),
      DATA_DIR: dataDir,
      CODEX_CWD: workspaceDir,
      CWD_ROOTS: workspaceDir,
      CODEX_SESSIOND_AUTO_START: 'false',
      SESSION_SECRET: '0123456789abcdef0123456789abcdef',
      AUTH_MODE: 'totp',
      TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      PRINT_TOTP_QR: 'false',
      EXPOSE_TOTP_URI: 'false',
      TOTP_PROVISION_FILE: path.join(tmpDir, '.totp-provisioned')
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    const baseUrl = await waitForServerReady(proc, 20_000);
    return { baseUrl, proc, tmpDir };
  } catch (err) {
    await stopServerForTest(proc).catch(() => undefined);
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
    throw err;
  }
}

async function stopServerForTest(proc: ChildProcessWithoutNullStreams): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) return;
  proc.kill('SIGTERM');
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      if (proc.exitCode === null && proc.signalCode === null) {
        proc.kill('SIGKILL');
      }
    }, 3_000);
    proc.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

async function loginAndGetSessionCookie(baseUrl: string): Promise<string> {
  const code = authenticator.generate('JBSWY3DPEHPK3PXP');
  const resp = await fetch(`${baseUrl}/api/auth/totp/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code })
  });
  assert.equal(resp.status, 200, 'TOTP login should succeed');
  const setCookie = resp.headers.get('set-cookie');
  assert.ok(setCookie, 'sid cookie should be set after login');
  return setCookie.split(';', 1)[0];
}

async function openTerminalSocket(wsUrl: string, cookie: string): Promise<WebSocket> {
  return await new Promise<WebSocket>((resolve, reject) => {
    const socket = new WebSocket(wsUrl, {
      headers: { cookie }
    });
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error('ws_open_timeout'));
    }, 5_000);
    socket.once('open', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function waitForTerminalOutput(socket: WebSocket, needle: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    let textBuf = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`terminal_output_timeout needle=${needle} output=${textBuf}`));
    }, 8_000);

    const onMessage = (raw: WebSocket.RawData) => {
      const chunk = (() => {
        if (typeof raw === 'string') return raw;
        if (raw instanceof Buffer) return raw.toString('utf8');
        if (raw instanceof ArrayBuffer) return Buffer.from(raw).toString('utf8');
        return Buffer.concat(raw).toString('utf8');
      })();
      textBuf += chunk;
      if (textBuf.includes(needle)) {
        cleanup();
        resolve(textBuf);
      }
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error(`socket_closed_before_output needle=${needle} output=${textBuf}`));
    };

    const cleanup = () => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
      socket.off('close', onClose);
    };

    socket.on('message', onMessage);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

describe('terminal api integration', () => {
  let started: StartedServer;

  before(async () => {
    started = await startServerForTest();
  });

  after(async () => {
    await stopServerForTest(started.proc);
    await fs.rm(started.tmpDir, { recursive: true, force: true });
  });

  test('POST /api/terminal requires auth', async () => {
    const resp = await fetch(`${started.baseUrl}/api/terminal`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(resp.status, 401);
    const body = await resp.json();
    assert.equal(body.ok, false);
    assert.equal(body.error, 'unauthorized');
  });

  test('POST /api/terminal creates a terminal and GET /api/terminals lists it', async () => {
    const cookie = await loginAndGetSessionCookie(started.baseUrl);

    const createResp = await fetch(`${started.baseUrl}/api/terminal`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie
      },
      body: JSON.stringify({})
    });
    assert.equal(createResp.status, 200);
    const createBody = await createResp.json();
    assert.equal(createBody.ok, true);
    assert.equal(typeof createBody.terminal?.terminalId, 'string');
    assert.equal(createBody.terminal?.cwd, path.resolve(path.join(started.tmpDir, 'workspace')));

    const listResp = await fetch(`${started.baseUrl}/api/terminals`, {
      headers: { cookie }
    });
    assert.equal(listResp.status, 200);
    const listBody = await listResp.json();
    assert.equal(listBody.ok, true);
    assert.ok(Array.isArray(listBody.terminals));
    assert.ok(
      listBody.terminals.some((item: any) => item.terminalId === createBody.terminal.terminalId),
      'created terminal should appear in listing'
    );
  });

  test('terminal websocket streams shell output', async () => {
    const cookie = await loginAndGetSessionCookie(started.baseUrl);
    const createResp = await fetch(`${started.baseUrl}/api/terminal`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie
      },
      body: JSON.stringify({})
    });
    assert.equal(createResp.status, 200);
    const createBody = await createResp.json();
    const terminalId = String(createBody.terminal?.terminalId || '');
    assert.ok(terminalId.length > 0, 'terminal id should exist');

    const wsUrl = `${started.baseUrl.replace(/^http/, 'ws')}/ws/terminal?terminalId=${encodeURIComponent(terminalId)}`;
    const socket = await openTerminalSocket(wsUrl, cookie);
    try {
      const marker = `__terminal_ws_ok_${Date.now()}__`;
      socket.send(`echo ${marker}\n`);
      const output = await waitForTerminalOutput(socket, marker);
      assert.match(output, new RegExp(marker));
    } finally {
      socket.close();
    }
  });

  test('compat path /codex/api/terminals is also available', async () => {
    const cookie = await loginAndGetSessionCookie(started.baseUrl);
    const resp = await fetch(`${started.baseUrl}/codex/api/terminals`, {
      headers: { cookie }
    });
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.terminals));
  });
});
