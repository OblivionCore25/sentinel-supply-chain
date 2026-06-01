/**
 * WebSocket service for real-time dashboard updates.
 * Connects to the Notification Service WebSocket endpoint.
 */

export type EventType = 'RISK_SCORE' | 'ALERT' | 'CONNECTION';

export interface WebSocketMessage {
  type: EventType;
  payload: unknown;
}

type MessageHandler = (message: WebSocketMessage) => void;

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8083/ws/dashboard';
const RECONNECT_INTERVAL = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

class WebSocketService {
  private ws: WebSocket | null = null;
  private handlers: Set<MessageHandler> = new Set();
  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  private _isConnected = false;
  private connectionListeners: Set<(connected: boolean) => void> = new Set();

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        console.log('[WS] Connected to Sentinel notification feed');
        this.reconnectAttempts = 0;
        this._isConnected = true;
        this.notifyConnectionChange(true);
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          this.handlers.forEach((handler) => handler(message));
        } catch (e) {
          console.warn('[WS] Failed to parse message:', e);
        }
      };

      this.ws.onclose = (event) => {
        console.log('[WS] Disconnected:', event.code, event.reason);
        this._isConnected = false;
        this.notifyConnectionChange(false);
        this.scheduleReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[WS] Error:', error);
      };
    } catch (e) {
      console.error('[WS] Connection failed:', e);
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = MAX_RECONNECT_ATTEMPTS; // Prevent reconnect
    this.ws?.close(1000, 'Client disconnecting');
    this.ws = null;
    this._isConnected = false;
    this.notifyConnectionChange(false);
  }

  subscribe(handler: MessageHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  onConnectionChange(listener: (connected: boolean) => void): () => void {
    this.connectionListeners.add(listener);
    // Immediately notify of current state
    listener(this._isConnected);
    return () => this.connectionListeners.delete(listener);
  }

  get isConnected(): boolean {
    return this._isConnected;
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      console.warn('[WS] Max reconnect attempts reached');
      return;
    }

    const delay = RECONNECT_INTERVAL * Math.pow(1.5, this.reconnectAttempts);
    console.log(`[WS] Reconnecting in ${Math.round(delay)}ms (attempt ${this.reconnectAttempts + 1})`);

    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectAttempts++;
      this.connect();
    }, delay);
  }

  private notifyConnectionChange(connected: boolean): void {
    this.connectionListeners.forEach((listener) => listener(connected));
  }
}

// Singleton instance
export const wsService = new WebSocketService();
