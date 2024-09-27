import os
import re
import dAngr.exceptions.FileNotFoundError

class ScriptProcessor:
    def __init__(self, script_path):
        self.script_path = script_path
    
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
        while True:
            line = next(file_obj, None)
            if line is None:
                break
            if until(line):
                break
            l = line.rstrip()
            if line == "":
                continue
            if line.endswith(":"):
                # Read until indentation is back to 0
                indentation = line.find(line.lstrip())
                while True:
                    line = next(file_obj, None)
                    if line is None:
                        break
                    line = line.rstrip()
                    if line == "":
                        continue
                    if line.find(line.lstrip()) == indentation:
                        break
                    l += "\n" + line
            if l is not None:
                yield l

        # for line in file_obj:
        #     # Yield each line in a non-markdown file

        #     if line.strip() == "":
        #         continue
        #     yield line.strip()  # Yield each line without leading/trailing whitespace

    def process_markdown(self, file_obj):

        for line in file_obj:
            line = line.rstrip()
            if line.strip() == "":
                continue
            # Handle inline code (between single backticks)
            inline_code_matches = re.findall(r'`([^`]+)`', line)
            for code in inline_code_matches:
                yield f"{code}"

            # Handle code blocks (between triple backticks or triple single quotes)
            prefix = line[:3]
            if prefix in ['```', "[[["]:
                postfix = '```' if prefix == '```' else ']]]'
                # Yield the collected code block lines
                for l in self.process_text(file_obj, lambda line:line.startswith(postfix)):
                    yield l


