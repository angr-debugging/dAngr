import os
import re

class ScriptProcessor:
    def __init__(self, script_path):
        self.script_path = script_path
    
    def is_markdown_file(self):
        return self.script_path.lower().endswith(('.md', '.markdown'))

    def process_file(self):
        with open(self.script_path, 'r') as f:
            if os.path.dirname(self.script_path):
                os.chdir(os.path.dirname(self.script_path))
            
            if self.is_markdown_file():
                yield from self.process_markdown(f)
            else:
                yield from self.process_text(f)

    def process_text(self, file_obj):
        for line in file_obj:
            # Yield each line in a non-markdown file
            if line.strip() == "":
                continue
            yield line.strip()  # Yield each line without leading/trailing whitespace

    def process_markdown(self, file_obj):
        inside_code_block = False
        code_block_lines = []

        for line in file_obj:
            line = line.rstrip()
            if line.strip() == "":
                continue
            # Handle inline code (between single backticks)
            inline_code_matches = re.findall(r'`([^`]+)`', line)
            for code in inline_code_matches:
                yield f"{code}"

            # Handle code blocks (between triple backticks or triple single quotes)
            if line.startswith('```') or line.startswith('```'):
                if inside_code_block:
                    inside_code_block = False
                    # Yield the collected code block lines
                    for code_line in code_block_lines:
                        yield f"{code_line}"
                    code_block_lines = []
                else:
                    inside_code_block = True
            elif inside_code_block:
                if line.startswith('```') or line.startswith('```'):
                    inside_code_block = False
                    # Yield the collected code block lines
                    for code_line in code_block_lines:
                        yield f"{code_line}"
                    code_block_lines = []
                else:
                    # Collect code block lines
                    code_block_lines.append(line)
                    
        # Handle any remaining code block lines if file ends
        if inside_code_block:
            for code_line in code_block_lines:
                yield f"Code block line: {code_line}"

