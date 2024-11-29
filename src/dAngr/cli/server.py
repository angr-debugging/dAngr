import html
import os

from prompt_toolkit import PromptSession

from prompt_toolkit.completion import WordCompleter, merge_completers, PathCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML



from dAngr.cli import  CommandLineDebugger
from dAngr.cli.cli_connection import CliConnection
from dAngr.cli.command_line_debugger import DEBUGGER_COMMANDS

from dAngr.cli.script_processor import ScriptProcessor

# add logger
from dAngr.utils.loggers import get_logger
logger = get_logger(__name__)

DEBUG_COMMANDS = False
class Server:
    def __init__(self, debug_file_path = None, script_path=None):
        logger.info("Initializing dAngr server with debug_file_path: %s and script_path: %s", debug_file_path, script_path)

        self.commands = DEBUGGER_COMMANDS
        dd = {c: f"{c} ({self.commands[c].short_name})" for c in self.commands.keys()}
        dd.update({self.commands[c].package + '.' + c: f"{c}" for c in self.commands.keys()})
        self.completer = merge_completers([WordCompleter(sorted(dd.keys()),display_dict=dd),PathCompleter(get_paths=lambda: [os.getcwd()])])
        self.debug_file_path = debug_file_path
        self.script_path = script_path
        self.stop = False
    
    def loop(self):
        conn = CliConnection()
        dbg = CommandLineDebugger(conn)
        conn.send_info("Welcome to dAngr, the symbolic debugger. Type help or ? to list commands.")
        prmpt = HTML('<darkcyan>(dAngr)> </darkcyan>')
        session = PromptSession(enable_history_search=True)
        if self.debug_file_path:
            dbg.handle(f"load {self.debug_file_path}", False)
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
                            l = line
                            if '\n' in line:
                                l = line.replace('\n', '\n' + " "*10)
                            prmpt2 = HTML(f'<darkcyan>(dAngr)> </darkcyan> {html.escape(l.strip())}')
                        try:
                            inp = session.prompt(prmpt2, completer=self.completer)
                            if not line.strip().startswith("#"):
                                # line = self._preprocess_input(conn, line)
                                if not dbg.handle(line, False):
                                    self.stop = True
                        except KeyboardInterrupt:
                            self.stop = True
                        except EOFError:
                            return # Ctrl-D to exit
                        except Exception as e:
                            if DEBUG_COMMANDS:
                                raise e
                            else:
                                conn.send_error(f"An unexpected error occurred: {e}")
                    if self.stop:
                        break
            except Exception as e:
                if DEBUG_COMMANDS:
                    raise e
                else:
                    conn.send_error(f"Error during script handling of {self.script_path}: {str(e)}")
                return
        self.stop = False
        self.script_path = None
        inp = ""
        while not self.stop:
            try:
                with patch_stdout() as po:
                    last_command = inp
                    inp = session.prompt(prmpt, completer=self.completer)
                    if inp.strip() == "":
                        inp = last_command
                    lines = inp
                    if inp.strip() == "":
                        continue
                    if inp.rstrip().endswith(":"):
                        # process multiline input
                        lines = self.recusive_line_handler(session, lines, 4)

                    # lines = self._preprocess_input(conn, lines)
                    if not lines:
                        continue
                    if not dbg.handle(lines, False):
                        self.stop = True
            except KeyboardInterrupt:
                return # Ctrl-C to exit
            except EOFError:
                return # Ctrl-D to exit
            except Exception as e:
                if DEBUG_COMMANDS:
                    raise e
                else:
                    conn.send_error(f"An unexpected error occurred: {e}")
    
    def recusive_line_handler(self, session: PromptSession, lines: str, line_indents: int) -> str:
        prompt_indents =  " "*(8 + line_indents)
        while True:
            line = session.prompt(prompt_indents + "", completer=self.completer)
            
            if line.strip() == "":
                return lines
            elif line.rstrip().endswith(":"):
                lines = self.recusive_line_handler(session, lines + f"\n{" "*line_indents}" + line, line_indents + 4)
            else:
                lines += f"\n{" "*line_indents}" + line

    
    def start_server(self):
        self.loop()

