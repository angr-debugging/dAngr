import os
from dAngr.cli.debugger_commands.base import BaseCommand
from dAngr.exceptions import DebuggerCommandError
import angrutils

class GetCfgCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Return the control flow graph in dot format."

    async def execute(self): # type: ignore
        try:
            import pygraphviz as pgv # type: ignore
        except ImportError:
            raise DebuggerCommandError("Please install pygraphviz to use this command.")

        cfg = self.debugger.cfg

        # G = pgv.AGraph(strict=False, directed=True)

        # for node in cfg.graph.nodes():
        #     func_name = cfg.kb.functions.get(node.function_address, None)
        #     func_name = func_name.name if func_name else "unknown"
        #     G.add_node(node.addr, label=f"{func_name}\n{hex(node.addr)}")

        # for edge in cfg.graph.edges():
        #     G.add_edge(edge[0].addr, edge[1].addr)
        # # dot_path = "cfg.dot"

        base_path = self.debugger.launch_file_server()
        file_index = 1 + len([name for name in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, name))])
        filename = "cfg_" + str(file_index)
        svg_path = f"{base_path}/{filename}"
        angrutils.plot_cfg(cfg, svg_path, asminst=True, vexinst=False, remove_imports=True, remove_path_terminator=True, format="svg")

        #G.draw(svg_path, prog='dot', format='svg')
        return f"http://localhost:8000/{filename}.svg"
