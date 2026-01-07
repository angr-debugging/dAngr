from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dAngr.angr_ext.debugger import Debugger

from typing import Optional
from angr import SimulationManager
from dataclasses import dataclass

from enum import Enum
import networkx as nx
import math


@dataclass
class TSConfig:
    target_address: int | None = None
    debugger: Debugger | None = None

@dataclass
class SearchTechniqueConfig:
    debugger: Debugger | None = None


class SearchTechnique(Enum):
    DFS = SearchTechniqueConfig()
    BFS = SearchTechniqueConfig()
    TS = TSConfig()

    def set_target_address(self, address: Optional[int]) -> None:
        if self is not SearchTechnique.TS:
            return None
        self.value.target_address = address

    def get_target_address(self) -> Optional[int]:
        if self is not SearchTechnique.TS:
            return None
        return self.value.target_address
    
    # Initialise any parameters needed for the search technique
    def initialise(self, debugger: Debugger, **kwargs) -> bool:
        self.value.debugger = debugger
        if self == SearchTechnique.TS:
            target_address = kwargs.get('target_address', None)
            if(target_address is None):
                self.value.debugger.conn.send_error("'target_address' must be specified for TS search technique.")
                return False

            self.set_target_address(target_address)
        return True

    def selector_func(self, run_ctx):
        if self in (SearchTechnique.DFS, SearchTechnique.BFS, SearchTechnique.TS):
            return lambda state: state == run_ctx.simgr.one_active
        raise ValueError(self)

    def after_step(self, run_ctx, simgr: SimulationManager, stepped_state):
        if self == SearchTechnique.DFS:
            return  # keep going deep
        
        if self == SearchTechnique.BFS:
            # rotate the just-stepped state to the back if still active
            if stepped_state in simgr.active and simgr.active and simgr.active[0] is stepped_state:
                simgr.active.pop(0)
                simgr.active.append(stepped_state)
            return

        if self == SearchTechnique.TS:
            target = self.get_target_address()
            if target is None:
                return

            # Build CFG once
            if not hasattr(self, "_ts_cfg"):
                self._ts_cfg = run_ctx.project.analyses.CFGFast()
            cfg = self._ts_cfg

            g = cfg.model.graph

            dst = cfg.model.get_any_node(int(target), anyaddr=True)
            if dst is None:
                return

            rev = g.reverse(copy=False)
            dist_to_target = dict(nx.single_source_shortest_path_length(rev, dst))

            def distance_to_target(state):
                try:
                    addr = state.addr
                    if not isinstance(addr, int):
                        addr = state.solver.eval(addr)
                except Exception as e:
                    return math.inf

                src = cfg.model.get_any_node(addr, anyaddr=True)
                if src is None:
                    return math.inf

                d = dist_to_target.get(src, math.inf)
                return d

            # Debug before sorting: compute distances once so we can log summary
            distances = []
            inf_count = 0
            for st in simgr.active:
                d = distance_to_target(st)
                distances.append((d, st))
                if d == math.inf:
                    inf_count += 1

            # Log the 10 closest states (by distance)
            for d, st in sorted(distances, key=lambda x: x[0])[:10]:
                try:
                    a = st.addr if isinstance(st.addr, int) else st.solver.eval(st.addr)
                except Exception:
                    a = None

            # Now sort using the precomputed distances (avoids recomputing inside sort)
            dist_map = {id(st): d for d, st in distances}
            simgr.active.sort(key=lambda st: dist_map.get(id(st), math.inf))

            return
        raise ValueError(self)