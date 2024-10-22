import os
import re
import dAngr.exceptions.FileNotFoundError

class ScriptProcessor:
    def __init__(self, script_path):
        self.script_path = script_path
        self.curdir = os.path.realpath(os.curdir)
    
    #destructor
    def __del__(self):
        os.chdir(self.curdir)
    
    def is_markdown_file(self):
        return self.script_path.lower().endswith(('.md', '.markdown'))

    def process_file(self):
        if not os.path.exists(self.script_path):
            raise FileNotFoundError(f"File '{self.script_path}' not found.")
        with open(self.script_path, 'r') as f:
            if os.path.dirname(self.script_path):
                os.chdir(os.path.dirname(self.script_path))
            
            if self.is_markdown_file():
                yield from self.process_markdown(f)
            else:
                yield from self.process_text(f)

    def process_text(self, file_obj, until=lambda line: False):
        # if definition or control flow (end with :), read until back to 0 indentation
        l = ""
        line = None
        stack = False
        while True:
            if not line:
                line = next(file_obj, None)
            if line is None:
                break
            if until(line):
                if l:
                    yield l
                break
            if line == "":
                line = None
                continue
            if line.strip('\r\n').endswith(":"):
                stack = True
            elif line.find(line.lstrip()) == 0:
                stack = False
            if stack:
                l += "\n" + line.rstrip() if l else line.rstrip()
                line = None
            else:
                if l:
                    yield l
                    l = ""
                else:
                    yield line.strip()
                    line = None

    def process_markdown(self, file_obj):

        for line in file_obj:
            line = line.rstrip()
            if line.strip() == "":
                continue
            # Handle inline code (between single backticks)
            inline_code_matches = re.findall(r'`([^`]+)`', line)
            for code in inline_code_matches:
                yield f"{code}".strip()

            # Handle code blocks (between triple backticks or triple single quotes)
            prefix = line[:3]
            if prefix in ['```', "[[["]:
                postfix = '```' if prefix == '```' else ']]]'
                # Yield the collected code block lines
                for l in self.process_text(file_obj, lambda line:line.startswith(postfix)):
                    yield l.strip()


