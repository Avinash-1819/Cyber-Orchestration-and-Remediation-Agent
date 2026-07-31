import { wsUrl } from './api';

type MessageHandler = (msg: any) => void;

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers: Set<MessageHandler> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;

  constructor(sessionId: string, token: string) {
    this.url = wsUrl(sessionId, token);
  }

  connect() {
    this.ws = new WebSocket(this.url);

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handlers.forEach(h => h(data));
    };

    this.ws.onclose = () => {
      if (this.shouldReconnect) {
        this.reconnectTimer = setTimeout(() => this.connect(), 3000);
      }
    };
  }

  subscribe(handler: MessageHandler) {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  disconnect() {
    this.shouldReconnect = false;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
    }
  }
}
