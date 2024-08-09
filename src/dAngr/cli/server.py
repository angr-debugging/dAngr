import asyncio
import os

from prompt_toolkit import PromptSession
from prompt_toolkit.application import get_app
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window, ScrollablePane
from prompt_toolkit.layout.containers import HSplit, VSplit
from prompt_toolkit.widgets import TextArea, SearchToolbar
from prompt_toolkit.completion import WordCompleter, merge_completers, PathCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML
from prompt_toolkit.keys import Keys
from prompt_toolkit.search import start_search, stop_search

from dAngr.cli import DEBUGGER_COMMANDS, CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.script_processor import ScriptProcessor

# add logger
import logging

from dAngr.utils.utils import DEBUG
logger = logging.getLogger("dAngr")



class Server:
    def __init__(self, debug_file_path = None, script_path=None):
        logger.info("Initializing dAngr server with debug_file_path: %s and script_path: %s", debug_file_path, script_path)
        print("Initializing dAngr server with debug_file_path: %s and script_path: %s", debug_file_path, script_path)

        self.commands = DEBUGGER_COMMANDS
        dbg = CommandLineDebugger(CliConnection())
        dd = {c: f">{c} ({self.commands[c](dbg).short_cmd_name})" for c in self.commands.keys()}
        self.completer = merge_completers([WordCompleter(sorted(dd.keys()),display_dict=dd),PathCompleter(get_paths=lambda: [os.getcwd()])])
        self.debug_file_path = debug_file_path
        self.script_path = script_path
        self.stop = False
    
    # def _create_key_bindings(self):
    #     # add key bindings
    #     kb = KeyBindings()
    #     @kb.add('c-c')
    #     def _(event):
    #         self.stop=True
    #         event.app.exit()

    async def loop(self):
        conn = CliConnection()
        dbg = CommandLineDebugger(conn)
        await conn.send_info("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
        prmpt = HTML('<darkcyan>(dAngr)> </darkcyan>')
        session = PromptSession(enable_history_search=True)
        if self.debug_file_path:
            await dbg.handle(f"load {self.debug_file_path}")
        if self.script_path:
            if os.path.dirname(self.script_path):
                os.chdir(os.path.dirname(self.script_path))
            proc:ScriptProcessor = ScriptProcessor(self.script_path)
            first = True
            for line in proc.process_file():
                #read script line by line and execute commands
                if line.strip() == "":
                    continue
                with patch_stdout() as po:
                    if first:
                        prmpt2 = HTML(f'<darkcyan>(dAngr)> </darkcyan> {line.strip()} <gray>(hit enter to proceed, Ctrl-c to end script)</gray>')
                        first = False
                    else:
                        prmpt2 = HTML(f'<darkcyan>(dAngr)> </darkcyan> {line.strip()}')
                    try:
                        inp = await session.prompt_async(prmpt2, completer=self.completer)
                        if not line.strip().startswith("#"):
                            if not await dbg.handle(line.strip()):
                                self.stop = True
                    except KeyboardInterrupt:
                        self.stop = True
                    except EOFError:
                        return # Ctrl-D to exit
                    except Exception as e:
                        if DEBUG:
                            raise e
                        else:
                            print(f"An unexpected error occurred: {e}")
                if self.stop:
                    break
        self.stop = False
        self.script_path = None
        while not self.stop:
            try:
                with patch_stdout() as po:
                    inp = await session.prompt_async(prmpt, completer=self.completer)
                    for user_input in inp.splitlines():
                        if not await dbg.handle(user_input):
                            self.stop = True
            except KeyboardInterrupt:
                return # Ctrl-C to exit
            except EOFError:
                return # Ctrl-D to exit
            except Exception as e:
                if DEBUG:
                    raise e
                else:
                    print(f"An unexpected error occurred: {e}")

    def start_server(self):
        asyncio.run(self.loop())

