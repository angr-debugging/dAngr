
from angr import SimStatePlugin


class StdoutTracker(SimStatePlugin):
    def __init__(self):
        super(StdoutTracker, self).__init__()
        self.stdout_mark = 0

    def set_mark(self):
        self.stdout_mark = len(self.state.posix.dumps(1))

    def get_new_output(self):
        start_len = self.stdout_mark
        full_output = self.state.posix.dumps(1)
        new_output = full_output[start_len:]
        self.set_mark()
        return new_output

    @SimStatePlugin.memo
    def copy(self, _memo):
        # This method is used by angr to copy the plugin when forking states
        new_plugin = StdoutTracker()
        new_plugin.stdout_mark = self.stdout_mark
        return new_plugin