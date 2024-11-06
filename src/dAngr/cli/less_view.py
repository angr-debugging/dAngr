
from html import unescape
from typing import List, Tuple
from prompt_toolkit import HTML
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit
from prompt_toolkit.widgets import TextArea, SearchToolbar,Label
from prompt_toolkit.key_binding.bindings import search
from prompt_toolkit.key_binding import ConditionalKeyBindings
from prompt_toolkit.filters.app import is_searching
from prompt_toolkit.filters.base import Condition
from prompt_toolkit.styles import Style

from dAngr.utils.utils import remove_xml_tags

class Less:

    def __init__(self):
        self.inner:TextArea = None # type: ignore
        self.search_field:SearchToolbar = None # type: ignore
        self.app:Application = None # type: ignore
        pass
            
    def show_less(self, txts:List[Tuple[str,Style|None]]):
        self.app = Application(
            layout=self._get_less_layout(texts=txts),
            key_bindings=self._get_less_key_bindings(),
            full_screen=True,
            mouse_support=True,
        )
        self.app.run()

    def _get_less_layout(self, texts:List[Tuple[str,Style|None]]):
        self.search_field = SearchToolbar()
        info = Label(HTML("<darkgray>Press 'ctrl-d' to exit, 'ctrl-f' to forward search, 'ctrl-r' for reverse search</darkgray>"))
        # TODO: display formatted text with styles
        txts = [unescape(remove_xml_tags(t[0])) for t in texts]
        self.inner = TextArea("\n".join(txts),scrollbar=True,read_only=True, search_field=self.search_field, multiline=True, wrap_lines=True, focus_on_click=True)
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