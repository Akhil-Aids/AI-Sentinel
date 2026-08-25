import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Shared authenticated WebSocket hook.
 *
 * - Authenticates via the same bearer token used by the REST API
 * - Auto-reconnects with exponential backoff (and resets after a stable
 *   connection)
 * - Exposes connection state and a `paused` flag so dashboards can freeze the
 *   live feed without losing the socket
 *
 * Messages are delivered through an `onMessage` callback that the caller
 * provides in the options object (stable across reconnects).
 */
export function useLiveSocket({ onMessage, enabled = true } = {}) {
  const [status, setStatus] = useState('connecting');
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled) return undefined;
    let disposed = false;
    let sock = null;
    let retry = null;
    let attempts = 0;

    const connect = () => {
      if (disposed) return;
      const token = localStorage.getItem('ai_sentinel_token');
      const base = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
      const url = `${base}${window.location.host}/ws/events`;
      sock = new WebSocket(url, token ? [`sentinel.${token}`] : []);
      sock.onopen = () => {
        if (disposed) return;
        attempts = 0;
        setStatus('connected');
      };
      sock.onclose = () => {
        if (disposed) return;
        setStatus('reconnecting');
        const delay = Math.min(15000, 1000 * 2 ** attempts);
        attempts += 1;
        retry = setTimeout(connect, delay);
      };
      sock.onerror = () => {
        sock?.close();
      };
      sock.onmessage = (ev) => {
        if (disposed || pausedRef.current) return;
        try {
          const msg = JSON.parse(ev.data);
          onMessageRef.current?.(msg);
        } catch (e) { /* ignore malformed frames */ }
      };
    };

    connect();
    return () => {
      disposed = true;
      sock?.close();
      if (retry) clearTimeout(retry);
    };
  }, [enabled]);

  const togglePause = useCallback(() => setPaused((p) => !p), []);

  return { status, paused, togglePause };
}
