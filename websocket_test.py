import asyncio
import websockets

WS_URL = "ws://127.0.0.1:8000/ws"


async def test_websocket():

    print("=" * 60)
    print("RANSOMGUARD WEBSOCKET LIVE TEST")
    print("=" * 60)

    print("\nConnecting to RansomGuard WebSocket...")

    async with websockets.connect(WS_URL) as websocket:

        print("WebSocket connected successfully!")
        print("Waiting for live threat events...\n")

        while True:

            message = await websocket.recv()

            print("=" * 60)
            print("[!] LIVE THREAT EVENT")
            print("=" * 60)
            print(message)
            print("=" * 60)


asyncio.run(test_websocket())