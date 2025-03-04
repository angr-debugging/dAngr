
import asyncio
import json
from typing import Type, TypeVar
import websockets


from dAngr.dap.common import parse_dap_message, parse_request
from dAngr.dap import dap_models
from dAngr.dap.dap_models import Request, Event, Response, Type2
from dAngr.exceptions import CommandError
from dAngr.angr_ext.connection import Connection

T = TypeVar('T', bound=dap_models.Response)
T2 = TypeVar('T2', bound=Event)

class DAPConnection(Connection):
    def __init__(self,socket:websockets.ServerConnection) -> None:
        self._socket = socket
    seq = 0
    def get_seq(self):
        self.seq += 1
        return self.seq

    def process_data(self,data) ->Request:
        _,message = parse_dap_message(data)
        print(f"Received message: {message}")
        # Process incoming messages from the client
        return parse_request(message)
    
    def send_info(self, data, style=None):
        self.send_sync(self._create_event(dap_models.OutputEvent, body=dap_models.Body6(output=data, data="{type:info}")))

    def send_result(self, data, newline=True, style=None) -> None:
        self.send_sync(self._create_event(dap_models.OutputEvent, body=dap_models.Body6(output=data, data="{type:result}")))

    def send_output(self, data, style=None) -> None:
        self.send_sync(self._create_event(dap_models.OutputEvent, body=dap_models.Body6(output=data, data="{type:output}")))

    def send_error(self, data, style=None) -> None:
        self.send_sync(self._create_ErrorResponse(data, None))
    
    async def send_req_error(self, data, request) -> None:
        self.send_sync(self._create_ErrorResponse(data, request=request))

    def send_warning(self, data, style=None) -> None:
        self.send_sync(self._create_event(dap_models.OutputEvent, body=dap_models.Body6(output=data, data="{type:warning}")))


    async def send(self,m:Response | Event):
        print(f"Sending response: {m}")
        json = m.model_dump_json().encode('ascii')
        content_length = len(json)
        header = f"Content-Length: {content_length}\r\n\r\n".encode('ascii')
        await self._socket.send(header + json)

    # async def send_sync(self, m:Response | Event):
    #     json = m.model_dump_json().encode('ascii')
    #     content_length = len(json)
    #     header = f"Content-Length: {content_length}\r\n\r\n".encode('ascii')
    #     await self._socket.send(header + json)
    def send_sync(self, m:Response | Event):
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(self.send(m))
        else:
            loop.run_until_complete(self.send(m))
            
    async def send_event(self, eventClass:Type[Event], **kwargs):
        await self.send(self._create_event(eventClass, **kwargs))
    def send_event_sync(self, eventClass:Type[Event], **kwargs):
        self.send_sync(self._create_event(eventClass, **kwargs))

    # async def send_output(self, output):
    #     await self.send(self._create_event(dap_models.OutputEvent, body=dap_models.Body6(output=output)))

    async def send_response(self, responseClass: Type[dap_models.Response], request, **kwargs):

        await self.send(self._create_response(responseClass, request, **kwargs))

    # async def send_error(self, error:Exception, request):
    #     await self.send(self._create_ErrorResponse(error, request))
    
    async def disconnect(self):
        await self._socket.close()

    def _create_response(self, cls: Type[T], r:dap_models.Request|None,success=True, **kwargs) -> T:
        """
        Generic function to create a specified type of Response with given values.

        :param cls: The class type of the response to create, subclass of BaseModel.
        :param kwargs: Keyword arguments to pass to the response class constructor.
        :return: An instance of the specified response class.
        """
        # Create and return an instance of the specified class with the given arguments
        return cls(seq = self.get_seq(),

            request_seq=r.seq if r and hasattr(r, 'seq') else 0,
                type = Type2.response,
                success = success,
                command=r.command if r and hasattr(r, 'command') else "unknown",
                **kwargs)

    def _create_event(self,cls: Type[T2], **kwargs) -> T2:
        """
        Generic function to create a specified type of Event with given values.

        :param cls: The class type of the event to create, subclass of BaseModel.
        :param kwargs: Keyword arguments to pass to the response class constructor.
        :return: An instance of the specified response class.
        """
        # Create and return an instance of the specified class with the given arguments
        event_name = cls.__name__.removesuffix('Event').lower()
        return cls.model_construct(seq = self.get_seq(),
                            type = 'event',
                            event=event_name,
                            **kwargs)
    

    def _create_ErrorResponse(self,e:Exception, request:dap_models.Request|None):
        req = request.command if request else "unknown"
        if type(e) is json.JSONDecodeError:
            error_message = dap_models.Message(
                id=1,  
                sendTelemetry=False,  # Whether to send telemetry
                format= f"An unexpected error occurred while parsing the request: {req}",  # Error message format
                variables={"error": f"{e}"},  # Variables to insert into the format
                showUser=False,  # Whether to show this error to the user
                url=None,  # URL for more information
                urlLabel=None  # Label for the URL
            )
        else:
            error_message = dap_models.Message(
                id=1,  
                sendTelemetry=False,  # Whether to send telemetry
                format= f"An unexpected error occurred while parsing the request: {req}",  # Error message format
                variables={"error": f"{e}"},  # Variables to insert into the format
                showUser=False,  # Whether to show this error to the user
                url=None,  # URL for more information
                urlLabel=None  # Label for the URL
            )
        error_response_body = dap_models.Body(error=error_message)
        
        return self._create_response(dap_models.ErrorResponse,request, body=error_response_body, success=False,message="Command failed")
   
