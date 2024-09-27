from antlr4.error.ErrorListener import ConsoleErrorListener

class ErrorListener(ConsoleErrorListener):
    def __init__(self):
        super(ErrorListener, self).__init__()
        self._errors = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        error_message = f"Syntax error at line {line}, column {column}: {msg}"
        self._errors.append(error_message)
        print(error_message)

    @property
    def errors(self):
        return self._errors
    
    def reportErrors(self):
        if self._errors:
            print(f"Found {len(self._errors)} error(s):")
            for error in self._errors:
                print(error)
        else:
            print("No syntax errors found.")