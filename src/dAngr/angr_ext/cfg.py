import angr
import threading
from collections import defaultdict
from typing import Callable, Any, Dict, List, Optional
from pathlib import Path
import traceback, logging

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from dAngr.cli.command_line_debugger import CommandLineDebugger
from dAngr.cli.debugger_commands.filters import FilterCommands

import networkx as nx
from networkx.readwrite import json_graph
from pytriskel.pytriskel import make_layout_builder


EventHandler = Callable[[Dict[str, Any], WebSocket], Any]
HERE = Path(__file__).resolve().parent
RES = HERE / "cfg_resources"

class ControlFlowGraphServer:
    def setup_server(self) -> None:
        self._handlers: Dict[str, List[EventHandler]] = defaultdict(list)
        self.app = FastAPI()

        self.app.mount("/static", StaticFiles(directory=str(RES / "static")), name="static")

        self._uvicorn_server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

        self._setup_routes()

    def __init__(self, project:angr.Project, debugger:CommandLineDebugger):
        self.project = project
        self.debugger = debugger
        
        self.cfg = self.project.analyses.CFG(
                show_progressbar=False,
                normalize=True,
                resolve_indirect_jumps=True,
                detect_tail_calls=True,
            )
        
        logging.getLogger(
            "angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX"
        ).setLevel(logging.CRITICAL)
        
        ccc = self.project.analyses.CompleteCallingConventions(analyze_callsites=True, cfg=self.cfg)

        self.setup_server()

    # ---------- Function CFG -------------------------------

    def function_callret_graph(self, add_returns: bool = True) -> nx.MultiDiGraph:
        """
        Nodes: functions (by address)
        Edges: caller -> callee (kind='call'), and optionally callee -> caller (kind='ret')
        """
        funcs = self.project.kb.functions
        cg = funcs.callgraph  # DiGraph: function_addr -> function_addr

        g = nx.MultiDiGraph()

        # add nodes with metadata
        for f_addr, f in funcs.items():
            g.add_node(f_addr, name=f.name, addr_hex=hex(int(f_addr)))

        # add call + return edges
        for caller, callee in cg.edges():
            if caller not in g or callee not in g:
                continue
            g.add_edge(caller, callee, kind="call")
            if add_returns:
                g.add_edge(callee, caller, kind="ret")

        return g


    def _function_to_cyto_triskel(self, func_addr: int, scale: float = 1.0):
        f = self.project.kb.functions[func_addr]
        g = f.graph  # per-function CFG (networkx DiGraph-like)

        builder = make_layout_builder()

        # Triskel requires the first node to be the "root"
        node_map = {}

        def node_key(n):
            a = getattr(n, "addr", None)
            return a if isinstance(a, int) else int(n)  # works for BlockNode/CFGNode/int

        entry = func_addr
        root_id = builder.make_node(hex(entry))
        node_map[entry] = root_id

        # Create remaining nodes
        for n in g.nodes():
            a = node_key(n)
            if a == entry:
                continue
            node_map[a] = builder.make_node(hex(a))

        # Create edges
        for src, dst in g.edges():
            sa = node_key(src)
            da = node_key(dst)
            if sa in node_map and da in node_map:
                builder.make_edge(node_map[sa], node_map[da])

        # (Optional) tune spacing
        # builder.set_x_gutter(50.0); builder.set_y_gutter(40.0); builder.set_edge_height(30.0)

        layout = builder.build()

        # Cytoscape expects node position at CENTER; Triskel coords are TOP-LEFT. :contentReference[oaicite:3]{index=3}
        nodes = []
        for addr, tid in node_map.items():
            pt = layout.get_coords(tid)
            w = layout.get_node_width(tid)
            h = layout.get_node_height(tid)

            x = (pt.x + w / 2.0) * scale
            y = (pt.y + h / 2.0) * scale

            nodes.append({
                "data": {"id": hex(addr), "label": hex(addr)},
                "position": {"x": x, "y": y}
            })

        edges = []
        for src, dst in g.edges():
            sa = hex(node_key(src))
            da = hex(node_key(dst))
            edges.append({"data": {"id": f"{sa}->{da}", "source": sa, "target": da}})

        return {"elements": nodes + edges}


    def cfg_json_to_svg(self, cfg_json: dict, out_path: str) -> str:
        from pytriskel.pytriskel import (
            make_layout_builder, make_svg_renderer,
            EdgeTypeDefault, EdgeTypeTrue, EdgeTypeFalse
        )
        import svgwrite

        nodes = cfg_json["nodes"]
        edges = cfg_json["edges"]

        # --- sizing knobs (match your SVG text) ---
        FONT_SIZE = 12
        LINE_PX = 14          # your dy step in tspans
        PAD_X = 12            # left+right padding total (roughly)
        PAD_TOP = 10
        PAD_BOTTOM = 10
        CHAR_PX = 7           # monospace approx width at 12px (tweak to taste)
        MIN_W = 80

        def node_lines(n: dict) -> list[str]:
            lines = [n["id"]]
            cap = n.get("capstone") or []
            cap = cap[1:]               # avoid first line
            lines += cap[:8]
            if len(cap) > 8:
                lines.append("…")
            return lines

        def measure(lines: list[str]) -> tuple[float, float]:
            max_len = max((len(s) for s in lines), default=1)
            w = max(MIN_W, (max_len * CHAR_PX) + PAD_X)
            h = PAD_TOP + FONT_SIZE + (len(lines) - 1) * LINE_PX + PAD_BOTTOM
            return float(w), float(h)

        b = make_layout_builder()

        node_idx = {}
        node_lines_map = {}

        # ✅ Create nodes with explicit (w,h) based on line count/content
        for n in nodes:
            lines = node_lines(n)
            node_lines_map[n["id"]] = lines
            w, h = measure(lines)
            node_idx[n["id"]] = b.make_node(w, h)   # <— key change (width,height) :contentReference[oaicite:1]{index=1}

        for e in edges:
            et = EdgeTypeDefault
            cond = e.get("condition")
            if cond is not None:
                s = str(cond).lower()
                if s in ("true", "1", "t", "yes"):
                    et = EdgeTypeTrue
                elif s in ("false", "0", "f", "no"):
                    et = EdgeTypeFalse
            b.make_edge(node_idx[e["src"]], node_idx[e["dst"]], et)

        # If you set explicit sizes, you don't need measure_nodes().
        # Keeping it is usually fine, but it’s meant for label-based sizing. :contentReference[oaicite:2]{index=2}
        # renderer = make_svg_renderer()
        # b.measure_nodes(renderer)

        layout = b.build()

        W = layout.get_width() + 40
        H = layout.get_height() + 40
        dwg = svgwrite.Drawing(out_path, size=(W, H))

        marker = dwg.marker(insert=(10, 5), size=(10, 10), orient="auto", id="arrow")
        marker.add(dwg.path(d="M 0 0 L 10 5 L 0 10 z", fill="black"))
        dwg.defs.add(marker)

        for e in edges:
            si = node_idx[e["src"]]
            di = node_idx[e["dst"]]

            sp = layout.get_coords(si)
            dp = layout.get_coords(di)

            sw = layout.get_node_width(si)
            sh = layout.get_node_height(si)
            dw = layout.get_node_width(di)

            x1 = sp.x + sw / 2 + 20
            y1 = sp.y + sh + 20
            x2 = dp.x + dw / 2 + 20
            y2 = dp.y + 20

            midy = (y1 + y2) / 2
            path = f"M {x1},{y1} L {x1},{midy} L {x2},{midy} L {x2},{y2}"
            dwg.add(dwg.path(d=path, fill="none", stroke="black",
                            marker_end=marker.get_funciri()))

        for n in nodes:
            i = node_idx[n["id"]]
            p = layout.get_coords(i)
            w = layout.get_node_width(i)
            h = layout.get_node_height(i)

            x = p.x + 20
            y = p.y + 20

            dwg.add(dwg.rect(insert=(x, y), size=(w, h), rx=6, ry=6,
                            fill="white", stroke="black"))

            lines = node_lines_map[n["id"]]

            text = dwg.text("", insert=(x + 6, y + 16),
                            font_family="monospace", font_size=f"{FONT_SIZE}px")
            for j, line in enumerate(lines):
                text.add(dwg.tspan(line, x=[x + 6], dy=[0 if j == 0 else LINE_PX]))
            dwg.add(text)

        dwg.save()
        return out_path
    
    def cfg_json_to_layout(self, cfg_json: dict) -> dict:
        from pytriskel.pytriskel import (
            make_layout_builder,
            EdgeTypeDefault, EdgeTypeTrue, EdgeTypeFalse
        )

        nodes = cfg_json["nodes"]
        edges = cfg_json["edges"]

        # --- sizing knobs (same as before) ---
        FONT_SIZE = 13
        LINE_PX = 15
        PAD_X = 120
        PAD_TOP = 5
        PAD_BOTTOM = 5
        CHAR_PX = 15
        MIN_W = 80

        def node_lines(n: dict) -> list[str]:
            lines = [n["id"]]
            cap = (n.get("capstone") or [])[1:]  # avoid first line
            lines += cap
            return lines

        def measure(lines: list[str]) -> tuple[float, float]:
            max_len = max((len(s) for s in lines), default=1)
            w = max(MIN_W, (max_len * CHAR_PX) + PAD_X)
            h = PAD_TOP + FONT_SIZE + (len(lines) - 1) * LINE_PX + PAD_BOTTOM
            return float(w), float(h)

        b = make_layout_builder()

        node_obj = {}     # node id -> triskel node object
        node_size = {}    # node id -> (w, h)

        for n in nodes:
            lines = node_lines(n)
            w, h = measure(lines)
            node_size[n["id"]] = (w, h)
            node_obj[n["id"]] = b.make_node(w, h)

        for e in edges:
            et = EdgeTypeDefault
            cond = e.get("condition")
            if cond is not None:
                s = str(cond).lower()
                if s in ("true", "1", "t", "yes"):
                    et = EdgeTypeTrue
                elif s in ("false", "0", "f", "no"):
                    et = EdgeTypeFalse
            b.make_edge(node_obj[e["src"]], node_obj[e["dst"]], et)

        layout = b.build()

        # --- extract placements ---
        placed_nodes = {}
        for n in nodes:
            nid = n["id"]
            p = layout.get_coords(node_obj[nid])   # top-left in layout space
            w = layout.get_node_width(node_obj[nid])
            h = layout.get_node_height(node_obj[nid])

            placed_nodes[nid] = {
                "x": float(p.x),
                "y": float(p.y),
                "w": float(w),
                "h": float(h),
                # convenience if your renderer wants center coords:
                "cx": float(p.x + w / 2),
                "cy": float(p.y + h / 2),
            }

        return {
            "graph": {
                "width": float(layout.get_width()),
                "height": float(layout.get_height()),
            },
            "nodes": placed_nodes,
        }



    # ---------- public API (your "freedom" layer) ----------

    def on(self, event_type: str, handler: EventHandler) -> None:
        """Register an event listener. event_type examples: node_clicked, edge_clicked, recompute_cfg."""
        self._handlers[event_type].append(handler)

    def start_in_thread(self, host: str = "127.0.0.1", port: int = 8001) -> None:
        """Start a permanent webserver in a daemon thread."""
        config = uvicorn.Config(self.app, host=host, port=port, log_level="info")
        self._uvicorn_server = uvicorn.Server(config)

        def _run():
            if self._uvicorn_server is not None:
              self._uvicorn_server.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        print(f"Web UI: http://{host}:{port}")

    def stop(self) -> None:
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True

    # ---------- routes / serialization ----------

    def _setup_routes(self) -> None:
        @self.app.get("/", response_class=HTMLResponse)
        def index():
            return FileResponse(RES / "static" / "index.html")

        @self.app.get("/graph")
        def graph():
            return JSONResponse(self._cfg_to_cytoscape_elements())

        @self.app.get("/block/{addr_hex}")
        def block(addr_hex: str):
            # Simple “extra feature” example: fetch disassembly for a block.
            addr = int(addr_hex, 16)
            b = self.project.factory.block(addr)
            ins = [{"address": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str} for i in b.capstone.insns]
            return {"addr": hex(addr), "size": b.size, "instructions": ins}

        @self.app.get("/functions")
        def functions():
            funcs = [{"addr": hex(f.addr), "name": f.name} for f in self.cfg.kb.functions.values()]
            return JSONResponse({"functions": funcs})
        
        @self.app.get("/functions_graph")
        def functions_graph():
            fcgh = self.function_callret_graph(add_returns=False)
            return json_graph.node_link_data(fcgh, edges="links")
        
        @self.app.post("/load_function_assembly")
        async def load_function_assembly(request: Request):
            try:
                data = await request.json()

                node_id_raw = data.get("node_id")
                if node_id_raw is None:
                    return {"ok": False, "error": "Missing node_id"}

                if isinstance(node_id_raw, str):
                    function_addr = int(node_id_raw, 0)
                else:
                    function_addr = int(node_id_raw)

                function = self.project.kb.functions.get(function_addr)

                if function is None:
                    return {"ok": False, "error": f"Function not found in cfg.kb.functions for {hex(function_addr)}"}

                # --- nodes ---
                nodes = []
                allowed = set(int(a) for a in function.block_addrs_set)
                nodes_by_id = {}

                for n in self.cfg.graph.nodes():
                    addr = int(getattr(n, "addr", None) or 0)
                    node_id = f"0x{addr:x}"
                    size = getattr(n, "size", None)

                    if addr in allowed:
                        capstone_lines = []
                        try:
                            block = self.project.factory.block(addr, size=size)
                            asm = getattr(block, "capstone", None)
                            if asm is not None and getattr(asm, "insns", None) is not None:
                                capstone_lines = [str(insn) for insn in asm.insns]
                        except Exception:
                            pass

                        node = {
                            "id": node_id,
                            "addr": addr,
                            "size": size,
                            "capstone": capstone_lines,
                            "successors": []
                        }
                        nodes.append(node)
                        nodes_by_id[node_id] = node

                allowed_ids = set(nodes_by_id.keys())

                # --- edges ---
                edges = []
                graph = getattr(function, "graph", None)
                if graph is None:
                    return {"ok": False, "error": f"Function {function.name} has no .graph"}

                for src, dst, edata in graph.edges(data=True):
                    if not hasattr(src, "addr") or not hasattr(dst, "addr"):
                        continue
                    if src.addr is None or dst.addr is None:
                        continue

                    src_id = f"0x{int(src.addr):x}"
                    dst_id = f"0x{int(dst.addr):x}"

                    if src_id not in allowed_ids or dst_id not in allowed_ids:
                        continue

                    jumpkind = edata.get("jumpkind") or edata.get("type") or "unknown"
                    s_jump = str(jumpkind)

                    kind = "branch"
                    if "Ijk_Call" in s_jump:
                        kind = "call"
                    elif "Ijk_Ret" in s_jump:
                        kind = "ret"

                    condition = str(edata["condition"]) if "condition" in edata else None

                    edges.append({
                        "src": src_id,
                        "dst": dst_id,
                        "kind": kind,
                        "jumpkind": s_jump,
                        "condition": condition,
                    })
                    nodes_by_id[src_id]["successors"].append(dst_id)

                nodes.sort(key=lambda x: x["addr"])
                edges.sort(key=lambda e: (int(e["src"], 16), int(e["dst"], 16)))

                proto = function.prototype
                return_type = None
                arg_types = None
                if( proto is not None):
                    return_type = str(proto.returnty.c_repr())
                    arg_types = [str(arg.c_repr()) for arg in proto.args]

                result = {
                    "ok": True,
                    "function": {"addr": int(function.addr), "name": function.name},
                    "return_type": return_type,
                    "arg_types": arg_types,
                    "nodes": nodes,
                    "edges": edges,
                }

                location_nodes = self.cfg_json_to_layout(result)

                result["layout"] = location_nodes

                return result

            except Exception as e:
                # This turns the “500 with no info” into actionable data
                tb = traceback.format_exc()
                print(tb)
                return {"ok": False, "error": str(e), "traceback": tb}

        '''@self.app.websocket("/ws")
        async def ws_endpoint(ws: WebSocket):
            await ws.accept()
            try:
                while True:
                    msg = await ws.receive_json()
                    print("WS recv:", msg, flush=True)
                    etype = msg.get("type", "unknown")

                    # Built-in event: recompute CFG on demand
                    if etype == "recompute_cfg":
                        self.cfg = self.project.analyses.CFGFast()
                        await ws.send_json({
                            "type": "cfg_recomputed",
                            "nodes": len(self.cfg.graph.nodes()),
                            "edges": len(self.cfg.graph.edges()),
                        })

                    # Dispatch to your custom handlers
                    for h in self._handlers.get(etype, []):
                        out = h(msg, ws)
                        if hasattr(out, "__await__"):  # handler might be async
                            await out
            except WebSocketDisconnect:
                return'''
        
        @self.app.post("/manage_breakpoints_excludes")
        def manage_breakpoints_excludes(item: dict):
            item_type = item.get("item_type")
            action = item.get("action")
            addressHex = item.get("address")
            if(addressHex is None):
                return JSONResponse({"status": "error", "message": "Address is required"}, status_code=400)
            
            address = int(addressHex, 16)

            if(item_type not in ("breakpoint", "exclude") or
                action not in ("add", "remove") or
                not isinstance(address, int)):
                return JSONResponse({"status": "error", "message": "Invalid parameters"}, status_code=400)
            
            if(item_type == "breakpoint"):
                if(action == "add"):
                    FilterCommands(self.debugger).filter(False, FilterCommands(self.debugger).by_address(address))
                else: # action == "remove"
                    indexBreakpoint = None
                    for index, f in enumerate(self.debugger.breakpoints):
                        if(f.address == address):
                            indexBreakpoint = index
                            break
                    if( indexBreakpoint is not None ):
                        self.debugger.breakpoints.pop(indexBreakpoint)
            else: # item_type == "exclude"
                if(action == "add"):
                    FilterCommands(self.debugger).filter(True, FilterCommands(self.debugger).by_address(address))
                else: # action == "remove"
                    indexExclude = None
                    for index, f in enumerate(self.debugger.exclusions):
                        if(f.address == address):
                            indexExclude = index
                            break
                    if( indexExclude is not None ):
                        self.debugger.exclusions.pop(indexExclude)

            # Implement the logic to manage breakpoints and excludes here
            return JSONResponse({"status": "success", "item_type": item_type, "action": action, "address": address})
        

    def _cfg_to_cytoscape_elements(self) -> Dict[str, Any]:
        # Cytoscape wants: { elements: [ {data:{...}}, {data:{...}}, ... ] }
        nodes = []
        edges = []

        def node_id(n) -> str:
            # CFGFast nodes usually have .addr; fall back to str(n) if not.
            a = getattr(n, "addr", None)
            return hex(a) if isinstance(a, int) else str(n)

        for n in self.cfg.graph.nodes():
            a = getattr(n, "addr", None)
            nid = node_id(n)
            label = nid
            nodes.append({"data": {"id": nid, "label": label, "addr": nid}})

        for src, dst in self.cfg.graph.edges():
            sid = node_id(src)
            tid = node_id(dst)
            eid = f"{sid}->{tid}"
            edges.append({"data": {"id": eid, "source": sid, "target": tid}})

        return {"elements": nodes + edges}