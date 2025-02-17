import angr


class printf(angr.SimProcedure): #stubbed this function to get the key out of it
    def run(self, args): # type: ignore
        print(f"Running hooked print function in example_hooks.py: {args}")
        return None
