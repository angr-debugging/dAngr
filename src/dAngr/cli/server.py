import asyncio
import html
import os
import re

from prompt_toolkit import PromptSession

from prompt_toolkit.completion import WordCompleter, merge_completers, PathCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML

from prompt_toolkit.search import start_search, stop_search


from dAngr.cli import  CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS

from dAngr.cli.script_processor import ScriptProcessor

# add logger


from dAngr.utils.loggers import get_logger
logger = get_logger(__name__)

DEBUG_COMMANDS = True
class Server:
    def __init__(self, debug_file_path = None, script_path=None):
        logger.info("Initializing dAngr server with debug_file_path: %s and script_path: %s", debug_file_path, script_path)

        self.commands = DEBUGGER_COMMANDS
        dd = {c: f">{c} ({self.commands[c].short_name})" for c in self.commands.keys()}
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
            try:
                if os.path.dirname(self.script_path):
                    os.chdir(os.path.dirname(self.script_path))
                proc:ScriptProcessor = ScriptProcessor(os.path.basename(self.script_path))
                first = True
                for line in proc.process_file():
                    if not line:
                        continue
                    #read script line by line and execute commands
                    with patch_stdout() as po:
                        if first:
                            prmpt2 = HTML(f'<darkcyan>(dAngr)> </darkcyan> {html.escape(line).strip()} <gray>(hit enter to proceed, Ctrl-c to end script)</gray>')
                            first = False
                        else:
                            prmpt2 = HTML(f'<darkcyan>(dAngr)> </darkcyan> {html.escape(line.strip())}')
                        try:
                            inp = await session.prompt_async(prmpt2, completer=self.completer)
                            if not line.strip().startswith("#"):
                                # line = self._preprocess_input(conn, line)
                                
                                if not await dbg.handle(line):
                                    self.stop = True
                        except KeyboardInterrupt:
                            self.stop = True
                        except EOFError:
                            return # Ctrl-D to exit
                        except Exception as e:
                            if DEBUG_COMMANDS:
                                raise e
                            else:
                                await conn.send_error(f"An unexpected error occurred: {e}")
                    if self.stop:
                        break
            except Exception as e:
                if DEBUG_COMMANDS:
                    raise e
                else:
                    await conn.send_error(f"Error during script handling of {self.script_path}: {str(e)}")
                return
        self.stop = False
        self.script_path = None
        while not self.stop:
            try:
                with patch_stdout() as po:
                    inp = await session.prompt_async(prmpt, completer=self.completer)
                    lines = inp
                    if inp.strip() == "":
                        continue
                    if inp.rstrip().endswith(":"):
                        # process multiline input
                        while True:
                            inp = await session.prompt_async(" "*8, completer=self.completer)
                            if inp.strip() == "":
                                break
                            lines += "\n" + inp

                    # lines = self._preprocess_input(conn, lines)
                    if not lines:
                        continue
                    if not await dbg.handle(lines):
                        self.stop = True
            except KeyboardInterrupt:
                return # Ctrl-C to exit
            except EOFError:
                return # Ctrl-D to exit
            except Exception as e:
                if DEBUG_COMMANDS:
                    raise e
                else:
                    await conn.send_error(f"An unexpected error occurred: {e}")
    # def _preprocess_input(self, conn:CliConnection,line:str):
    #     """
    #     Preprocess the input line.
    #     """
    #     # remove comments
    #     line = line.split("#")[0]
    #     # remove leading and trailing whitespaces
    #     line = line.strip()
    #     # line may contain references marked as $<int> with int being the index back in the history of conn.history
    #     # replace them with the actual values
    #     for match in re.finditer(r"\$([0-9]+)", line):
    #         try:
    #             ix = int(match.group(1))
    #             if 0 <= ix < len(conn.history):
    #                 val = conn.history[ix][0][0]
    #                 line = line.replace(match.group(0), val)
    #         except IndexError:
    #             pass    
    #     return line
    
    def start_server(self):
        asyncio.run(self.loop())

