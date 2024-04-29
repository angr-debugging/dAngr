import asyncio

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML

from dAngr.cli import DEBUGGER_COMMANDS, CommandLineDebugger
from dAngr.cli.connection import CliConnection



class Server:
    def __init__(self):
        self.commands = DEBUGGER_COMMANDS
        self.completer = WordCompleter(self.commands.keys()) # merge_completers([WordCompleter(self.commands.keys()),ExecutableCompleter()])
        
    async def loop(self):
        conn = CliConnection()
        dbg = CommandLineDebugger(conn)
        await conn.send_event("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
        prmpt = HTML('<darkcyan>(dAngr)> </darkcyan>')
        session = PromptSession()
        stop = False
        while not stop:
            try:
                with patch_stdout() as po:
                    inp = await session.prompt_async(prmpt, completer=self.completer)
                    for user_input in inp.splitlines():
                        if not await dbg.handle(user_input):
                            stop = True
            except EOFError:
                break
            except Exception as e:
                print   (f"An error occurred: {e}")

    def start_server(self):
        asyncio.run(self.loop())

