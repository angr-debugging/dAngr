
from angr import SimStatePlugin


class StdTracker(SimStatePlugin):
    def __init__(self, stream:int=1):
        super(StdTracker, self).__init__()
        self.std_mark = 0
        self.prev_std_mark = 0
        self.stream = stream

    def set_mark(self):
        self.prev_std_mark = self.std_mark
        self.std_mark = len(self.state.posix.dumps(self.stream))

    def get_new_data(self)->bytes:
        start_len = self.std_mark
        full_output = self.state.posix.dumps(self.stream)
        new_output = full_output[start_len:]
        self.set_mark()
        return new_output
    
    def get_new_string(self)->str:
        return self.get_new_data().decode('utf-8')
    
    def get_prev_string(self)->str:
        if self.prev_std_mark == self.std_mark:
            return ''
        start_len = self.prev_std_mark
        full_output = self.state.posix.dumps(self.stream)
        return full_output[start_len:].decode('utf-8')

    @SimStatePlugin.memo
    def copy(self, _memo)-> SimStatePlugin: # type: ignore
        # This method is used by angr to copy the plugin when forking states
        new_plugin = StdTracker(stream=self.stream)
        new_plugin.std_mark = self.std_mark
        return new_plugin