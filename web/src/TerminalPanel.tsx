import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { terminalWsUrl, type TerminalSession } from './api';

type ConnectionState = 'connecting' | 'connected' | 'disconnected';

export default function TerminalPanel(props: {
  terminal: TerminalSession;
  onClose: () => void;
  onCopyId: (terminalId: string) => void | Promise<void>;
}) {
  const { terminal, onClose, onCopyId } = props;
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [reconnectSeq, setReconnectSeq] = useState(0);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    host.innerHTML = '';
    const fitAddon = new FitAddon();
    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
      fontSize: 13,
      lineHeight: 1.25,
      theme: {
        background: '#0b1118',
        foreground: '#f6f8fb',
        cursor: '#8ab4ff'
      }
    });
    term.loadAddon(fitAddon);
    term.open(host);

    const sendResize = (socket: WebSocket) => {
      try {
        fitAddon.fit();
      } catch {
        // Ignore transient layout errors during mount/unmount.
      }
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };

    const socket = new WebSocket(terminalWsUrl(terminal.terminalId));
    setConnection('connecting');

    let closed = false;
    socket.addEventListener('open', () => {
      if (closed) return;
      setConnection('connected');
      sendResize(socket);
      term.focus();
    });
    socket.addEventListener('message', (event) => {
      if (closed) return;
      if (typeof event.data === 'string') {
        term.write(event.data);
        return;
      }
      if (event.data instanceof Blob) {
        void event.data.text().then((text) => {
          if (!closed) term.write(text);
        });
      }
    });
    socket.addEventListener('close', () => {
      if (closed) return;
      setConnection('disconnected');
    });
    socket.addEventListener('error', () => {
      if (closed) return;
      setConnection('disconnected');
    });

    const onDataDisposable = term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(data);
    });

    const onWindowResize = () => sendResize(socket);
    window.addEventListener('resize', onWindowResize);

    const ro = typeof ResizeObserver !== 'undefined'
      ? new ResizeObserver(() => sendResize(socket))
      : null;
    ro?.observe(host);

    return () => {
      closed = true;
      ro?.disconnect();
      window.removeEventListener('resize', onWindowResize);
      onDataDisposable.dispose();
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
      term.dispose();
    };
  }, [terminal.terminalId, reconnectSeq]);

  const statusText = connection === 'connected'
    ? 'Connected'
    : connection === 'connecting'
      ? 'Connecting'
      : 'Disconnected';

  return (
    <div className="terminal-panel">
      <div className="terminal-panel-head">
        <div className="terminal-panel-title">
          <span>Active terminal</span>
          <span className="terminal-panel-id">{terminal.terminalId}</span>
        </div>
        <button className="btn btn-secondary btn-sm" type="button" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="terminal-panel-grid">
        <div className="muted">CWD</div>
        <div>{terminal.cwd || 'default'}</div>
        <div className="muted">Status</div>
        <div>{terminal.status || 'running'}</div>
        <div className="muted">Socket</div>
        <div>{statusText}</div>
        <div className="muted">Created</div>
        <div>{new Date(terminal.createdAt).toLocaleString()}</div>
      </div>

      <div className="terminal-live-wrap">
        <div ref={hostRef} className="terminal-live" />
      </div>

      <div className="row row-tight">
        <button className="btn btn-secondary btn-sm" type="button" onClick={() => setReconnectSeq((v) => v + 1)}>
          Reconnect
        </button>
        <button className="btn btn-secondary btn-sm" type="button" onClick={() => void onCopyId(terminal.terminalId)}>
          Copy terminal id
        </button>
      </div>
    </div>
  );
}
