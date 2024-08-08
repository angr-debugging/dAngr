import asyncio
from functools import partial
from prompt_toolkit import PromptSession
from prompt_toolkit.application.current import get_app
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import BufferControl
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import ThreadedCompleter, DynamicCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import DynamicAutoSuggest
from prompt_toolkit.layout.controls import FormattedTextControl

from prompt_toolkit.lexers import DynamicLexer
from prompt_toolkit.layout.processors import (
    ConditionalProcessor,
    HighlightIncrementalSearchProcessor,
    HighlightSelectionProcessor,
    DisplayMultipleCursors,
    PasswordProcessor,
    AppendAutoSuggestion,
    AfterInput,
    merge_processors,
    DynamicProcessor,
)
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.layout.menus import MultiColumnCompletionsMenu
from prompt_toolkit.filters import has_focus, is_done, Condition

from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.margins import ScrollbarMargin
from prompt_toolkit.layout.screen import Char
from prompt_toolkit.styles import (
    BaseStyle,
    ConditionalStyleTransformation,
    DynamicStyle,
    DynamicStyleTransformation,
    StyleTransformation,
    SwapLightAndDarkStyleTransformation,
    merge_style_transformations,
)
from prompt_toolkit.formatted_text import (
    AnyFormattedText,
    StyleAndTextTuples,
    fragment_list_to_text,
    merge_formatted_text,
    to_formatted_text,
)
from prompt_toolkit.utils import (
    get_cwidth,
    is_dumb_terminal,
    suspend_to_background_supported,
    to_str,
)

from typing import Callable
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.layout.utils import explode_text_fragments
_StyleAndTextTuplesCallable = Callable[[], StyleAndTextTuples]
E = KeyPressEvent

# Define the sample text for the less-like viewer
sample_text = "\n".join([f"Line {i}" for i in range(1, 101)])

def _split_multiline_prompt(
    get_prompt_text: _StyleAndTextTuplesCallable,
) -> tuple[
    Callable[[], bool], _StyleAndTextTuplesCallable, _StyleAndTextTuplesCallable
]:
    """
    Take a `get_prompt_text` function and return three new functions instead.
    One that tells whether this prompt consists of multiple lines; one that
    returns the fragments to be shown on the lines above the input; and another
    one with the fragments to be shown at the first line of the input.
    """

    def has_before_fragments() -> bool:
        for fragment, char, *_ in get_prompt_text():
            if "\n" in char:
                return True
        return False

    def before() -> StyleAndTextTuples:
        result: StyleAndTextTuples = []
        found_nl = False
        for fragment, char, *_ in reversed(explode_text_fragments(get_prompt_text())):
            if found_nl:
                result.insert(0, (fragment, char))
            elif char == "\n":
                found_nl = True
        return result

    def first_input_line() -> StyleAndTextTuples:
        result: StyleAndTextTuples = []
        for fragment, char, *_ in reversed(explode_text_fragments(get_prompt_text())):
            if char == "\n":
                break
            else:
                result.insert(0, (fragment, char))
        return result

    return has_before_fragments, before, first_input_line

class InteractiveSession:
    def __init__(self):
        self.session = PromptSession()

        self.less_active = False
        self.history = InMemoryHistory()
        self.completer = None
        self.complete_in_thread = False
        self.auto_suggest = None
        self.tempfile_suffix:str = ""
        self.tempfile:str = ""
        self.lexer = None
        self.message = "dAngr>>> "
        self.prompt_continuation = "..."
        self.complete_style = CompleteStyle.READLINE_LIKE
        def accept(buff):
            # Update display_area with the user input
            self.display_area.text += buff.text + "\n"
            self._update_layout()
            return True
        self.default_buffer = Buffer(name="prompt_buffer",
            complete_while_typing=True,
            validate_while_typing=False,
            enable_history_search=True,
            completer=DynamicCompleter(
                lambda: ThreadedCompleter(self.completer)
                if self.complete_in_thread and self.completer
                else self.completer
            ),
            history=self.history,
            auto_suggest=DynamicAutoSuggest(lambda: self.auto_suggest),
            accept_handler=accept,
            tempfile_suffix= self.tempfile_suffix,
            tempfile=lambda: self.tempfile,
        )
        
        all_input_processors = [
            HighlightIncrementalSearchProcessor(),
            HighlightSelectionProcessor(),
            ConditionalProcessor(
                AppendAutoSuggestion(), has_focus(self.default_buffer) & ~is_done
            ),
            DisplayMultipleCursors(),
        ]
        # create the prompt area with a prompt string that cannot be changed, and a multiline text area
        default_buffer_control = BufferControl(
            buffer=self.default_buffer,
            search_buffer_control=None,
            input_processors=all_input_processors,
            include_default_input_processors=False,
            lexer=DynamicLexer(lambda: self.lexer),
            preview_search=True,
        )
        (
            has_before_fragments,
            get_prompt_text_1,
            get_prompt_text_2,
        ) = _split_multiline_prompt(self._get_prompt)
        
        default_buffer_window = Window(
            default_buffer_control,
            height=self._get_default_buffer_control_height,
            get_line_prefix=partial(
                self._get_line_prefix, get_prompt_text_2=get_prompt_text_2
            ),
            wrap_lines=False,
        )

        self.prompt_area = HSplit([
             Window(
                    FormattedTextControl("dAngr>>> ", focusable=False, show_cursor=False),
                    dont_extend_height=True
                ),
            default_buffer_window
        ])

        # self.prompt_area = TextArea(
        #     text="dAngr>>> ",
        #     multiline=False,
        #     wrap_lines=False,
        #     focus_on_click=True
        # )
        self.display_area = TextArea(
            text=sample_text,
            read_only=True,
            scrollbar=True,
            line_numbers=True,
            wrap_lines=False
        )
        self.application:Application = Application(
            layout=self._get_layout(),
            key_bindings=self._get_key_bindings(),
            full_screen=True
        )

        # self.default_buffer.on_text_changed = self.on_text_changed
    
    def _get_prompt(self) -> StyleAndTextTuples:
        return to_formatted_text(self.message, style="class:prompt")
    
    def _get_line_prefix(
        self,
        line_number: int,
        wrap_count: int,
        get_prompt_text_2: _StyleAndTextTuplesCallable,
    ) -> StyleAndTextTuples:
        """
        Return whatever needs to be inserted before every line.
        (the prompt, or a line continuation.)
        """
        # First line: display the "arg" or the prompt.
        if line_number == 0 and wrap_count == 0:
                return get_prompt_text_2()

        # For the next lines, display the appropriate continuation.
        prompt_width = get_cwidth(fragment_list_to_text(get_prompt_text_2()))
        return self._get_continuation(prompt_width, line_number, wrap_count)
    
    # def on_text_changed(seflf_: object) -> None:
    #     self._update_layout()

    def _get_continuation(
        self, width: int, line_number: int, wrap_count: int
    ) -> StyleAndTextTuples:
        """
        Insert the prompt continuation.

        :param width: The width that was used for the prompt. (more or less can
            be used.)
        :param line_number:
        :param wrap_count: Amount of times that the line has been wrapped.
        """
        prompt_continuation = self.prompt_continuation

        if callable(prompt_continuation):
            continuation: AnyFormattedText = prompt_continuation(
                width, line_number, wrap_count
            )
        else:
            continuation = prompt_continuation

        
    def _get_default_buffer_control_height(self) -> Dimension:
        # If there is an autocompletion menu to be shown, make sure that our
        # layout has at least a minimal height in order to display it.
        if (
            self.completer is not None
            and self.complete_style != CompleteStyle.READLINE_LIKE
        ):
            space = 8
        else:
            space = 0

        if space and not get_app().is_done:
            buff = self.default_buffer

            # Reserve the space, either when there are completions, or when
            # `complete_while_typing` is true and we expect completions very
            # soon.
            if buff.complete_while_typing() or buff.complete_state is not None:
                return Dimension(min=space)

        return Dimension()
    
    def _get_key_bindings(self):
        kb = KeyBindings()
        handle = kb.add
        default_focused = has_focus("prompt_buffer")
        @kb.add("c-l")
        def _(event):
            self.less_active = True
            self._update_layout()

        @kb.add("c-c")
        def _(event):
            if not self.less_active:
                event.app.exit()
            else:
                self.less_active = False
                self._update_layout()
        @Condition
        def do_accept() -> bool:
            return self.application.layout.has_focus(
                "prompt_buffer"
            )
        @handle("enter", filter=do_accept & default_focused)
        def _accept_input(event: E) -> None:
            "Accept input when enter has been pressed."
            self.default_buffer.validate_and_handle()
        return kb


    
    def _get_layout(self):
        if self.less_active:
            return Layout(HSplit([self.display_area]))
        else:
            return Layout(HSplit([self.prompt_area]))

    def _update_layout(self):
        self.application.layout = self._get_layout()
        self.application.invalidate()

    async def run(self):
        # Run the application in the background
        await self.application.run_async()

        # asyncio.create_task(self.application.run_async())

        # while True:
        #     if not self.less_active:
                #    user_input = await self.session.prompt_async(">>> ")
        #         # if user_input.lower() in ('exit', 'quit'):
        #         #     break
        #         # Update prompt_area with the user input
        #         # self.prompt_area.text += user_input + "\n"
        #         self._update_layout()

if __name__ == "__main__":
    interactive_session = InteractiveSession()
    asyncio.run(interactive_session.run())
