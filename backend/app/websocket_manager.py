from datetime import datetime, timezone


class ConnectionManager:
    """
    Manages active WebSocket connections
    and broadcasts threat events to connected clients.
    """

    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message):

        # Inject ISO-8601 timestamp into every broadcast
        message["timestamp"] = datetime.now(timezone.utc).isoformat()

        disconnected = []
        client_count = len(self.active_connections)

        if client_count == 0:
            print("[WS BROADCAST] No connected clients — message dropped.")
            return

        for connection in self.active_connections:

            try:
                await connection.send_json(message)

            except Exception as exc:
                print(f"[WS BROADCAST] Send failed: {exc}")
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)

        sent = client_count - len(disconnected)
        print(f"[WS BROADCAST] Sent to {sent}/{client_count} client(s).")