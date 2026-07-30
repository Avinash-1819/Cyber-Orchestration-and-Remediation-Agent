type MessageHandler = (msg: any) => void;

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers: Set<MessageHandler> = new Set();

  constructor(sessionId: string, token: string) {
    this.url = `ws://localhost:8000/api/v1/ws/${sessionId}?token=${token}`;
  }

  connect() {
    this.ws = new WebSocket(this.url);
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handlers.forEach(h => h(data));
    };

    this.ws.onclose = () => {
      setTimeout(() => this.connect(), 3000);
    };
  }

  subscribe(handler: MessageHandler) {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}
