from angr import SimState
from dAngr.exceptions import DebuggerCommandError
from typing import List, Tuple, Dict
from bisect import bisect_left

def find_biggest_free_space(state:SimState, address:int, size:int):
    data_region_ptr = address
    state.memory.map_region(addr=data_region_ptr, length=size, permissions=3, init_zero=True)
    return data_region_ptr


class MemoryManagment():
    StartAddress = 0
    EndAddress = 0


    def __init__(self, state:SimState, address:int=0x900000000000000, size:int=0x100000) -> None:
        self.StartAddress = find_biggest_free_space(state, address, size) # 1 MiB
        self.EndAddress = self.StartAddress + size

        # free list: sorted by start, intervals are [start, start+size)
        self._free: List[Tuple[int, int]] = [(self.StartAddress, size)]
        # allocated map: addr -> size
        self._alloc: Dict[int, int] = {}

    def malloc(self, size: int):
        if size <= 0:
            raise ValueError("size must be > 0")
        
        # first fit algoritme -> fast and easy
        address_malloc = None
        for i, (start, size_buffer) in enumerate(self._free):
            if(size_buffer >= size):
                address_malloc = start
                self._free.pop(i)
                if size_buffer > size: 
                    self._free.insert(i, (address_malloc+size, size_buffer-size))
                break

        if address_malloc == None:
            raise ValueError("Memory is full!!")
        
        self._alloc[address_malloc] = size
        return address_malloc

    def _insert_and_coalesce(self, start: int, size: int) -> None:
        new_start = start
        new_end = start + size

        # find insert position to keep _free sorted by start
        i = 0
        while i < len(self._free) and self._free[i][0] < new_start:
            i += 1

        # merge with left neighbor if it touches or overlaps
        if i > 0:
            l_start, l_size = self._free[i - 1]
            l_end = l_start + l_size
            if l_end >= new_start:
                new_start = l_start
                new_end = max(new_end, l_end)
                i -= 1
                self._free.pop(i)

        # merge with all right neighbors that touch/overlap
        while i < len(self._free):
            r_start, r_size = self._free[i]
            r_end = r_start + r_size
            if r_start > new_end:
                break
            new_end = max(new_end, r_end)
            self._free.pop(i)

        # insert merged block
        self._free.insert(i, (new_start, new_end - new_start))

    def free(self, address: int):
        size = self._alloc.pop(address, None)
        if size is None:
            raise KeyError(f"Invalid free: {hex(address)} was not allocated")
        self._insert_and_coalesce(address, size)
