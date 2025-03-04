import asyncio
from json import JSONDecodeError
import signal
import sys

import websockets

from dAngr.dap.dap_connection import DAPConnection
from dAngr.dap.dap_debugger import DAPDebugger


class Server:
    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        self.server = None
        pass

    async def _handle_client_connection(self,client_socket):
        conn = DAPConnection(client_socket)
        h = DAPDebugger(conn)
        async for data in client_socket:
            try:
                message = conn.process_data(data)
                print(f"Received message from client: {message.command}")
                asyncio.create_task(h.handle_request(message))
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"Error: {e}", file=sys.stderr)
            except JSONDecodeError as e:
                print(f"Error: {e}", file=sys.stderr)
                await conn.send_req_error(e,message)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                conn.send_error(f"{e}: {data}")
        h = None

    def shutdown_server(self):
        print("Shutting down the server...")
        if self.server: 
            self.server.server.close()
            asyncio.get_event_loop().run_until_complete(self.server.wait_closed())

        # Close server resources here

    def signal_handler(self,signum, frame):
        self.shutdown_server()
        sys.exit(0)

    def start_server(self,host = "127.0.0.1", port = 5678):
        asyncio.run(self._start_server(host, port))
    
    async def _start_server(self, host, port):
        serve = websockets.serve(self._handle_client_connection, host, port)
        self.server = serve.server
        #run forever
        await serve
        await asyncio.Future()  # run forever