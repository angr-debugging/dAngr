from dAngr.cli.models import Response
from dAngr.cli.debugger_commands.base import BaseCommand

class GetCfgCommand(BaseCommand):
    def __init__(self, debugger_core):
        super().__init__(debugger_core)
        self.info = "Return the control flow graph in dot format."

    async def execute(self):
        try:
            import pygraphviz as pgv # type: ignore
        except ImportError:
            return Response("Please install pygraphviz to use this command.", "error")
        self.throw_if_not_initialized()
        cfg = self.debugger.getCFGFast()
        G = pgv.AGraph(strict=False, directed=True)

        for node in cfg.graph.nodes():
            func_name = cfg.kb.functions.get(node.function_address, None)
            func_name = func_name.name if func_name else "unknown"
            G.add_node(node.addr, label=f"{func_name}\n{hex(node.addr)}")

        for edge in cfg.graph.edges():
            G.add_edge(edge[0].addr, edge[1].addr)

        # dot_path = "cfg.dot"
        png_path = "cfg.png"
        # G.write(dot_path)
        G.draw(png_path, prog='dot', format='png')
        return Response({"graph":G.string(), "type": "dot"})
