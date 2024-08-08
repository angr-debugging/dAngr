
from prompt_toolkit import HTML
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit, VSplit
from prompt_toolkit.widgets import TextArea, SearchToolbar,Label
from prompt_toolkit.search import start_search
from prompt_toolkit.keys import Keys
from prompt_toolkit.key_binding.bindings import search
from prompt_toolkit.key_binding import ConditionalKeyBindings
from prompt_toolkit.filters.app import is_searching
from prompt_toolkit.filters.base import Condition

class Less:

    def __init__(self):
        self.inner:TextArea = None # type: ignore
        self.search_field:SearchToolbar = None # type: ignore
        self.app:Application = None # type: ignore
        pass
            
    async def show_less(self, txts):

        self.app = Application(
            layout=self._get_less_layout(texts=txts),
            key_bindings=self._get_less_key_bindings(),
            full_screen=True,
            mouse_support=True,
        )
        await self.app.run_async()

    def _get_less_layout(self, texts):
        self.search_field = SearchToolbar()
        info = Label(HTML("<darkgray>Press 'ctrl-d' to exit, 'ctrl-f' to forward search, 'ctrl-r' for reverse search</darkgray>"))
        self.inner = TextArea("\n".join(texts),scrollbar=True,read_only=True, search_field=self.search_field, multiline=True, wrap_lines=True, focus_on_click=True)
        return Layout(
                HSplit([ 
                    self.inner, 
                    self.search_field, 
                    info
                ])
                )

    def _get_less_key_bindings(self):
        kb = KeyBindings()
        
        @kb.add('c-d')
        def _(event):
            event.app.exit()
        

        # @kb.add('c-f')
        # def _(event):
        #     start_search(self.inner.control)
        
        handle = kb.add


        @Condition
        def search_buffer_is_empty() -> bool:
            "Returns True when the search buffer is empty."
            return self.app.current_buffer.text == ""

        handle("c-f")(search.start_forward_incremental_search)
        handle("c-r")(search.start_reverse_incremental_search)

        # Apply the search. (At the / or ? prompt.)
        handle("enter", filter=is_searching)(search.accept_search)

        handle("c-f", filter=is_searching)(search.forward_incremental_search)
        handle("c-s", filter=is_searching)(search.reverse_incremental_search)


        return ConditionalKeyBindings(kb)