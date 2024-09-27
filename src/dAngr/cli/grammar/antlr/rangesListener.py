# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/ranges.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .rangesParser import rangesParser
else:
    from rangesParser import rangesParser

# This class defines a complete listener for a parse tree produced by rangesParser.
class rangesListener(ParseTreeListener):

    # Enter a parse tree produced by rangesParser#statement.
    def enterStatement(self, ctx:rangesParser.StatementContext):
        pass

    # Exit a parse tree produced by rangesParser#statement.
    def exitStatement(self, ctx:rangesParser.StatementContext):
        pass


    # Enter a parse tree produced by rangesParser#range.
    def enterRange(self, ctx:rangesParser.RangeContext):
        pass

    # Exit a parse tree produced by rangesParser#range.
    def exitRange(self, ctx:rangesParser.RangeContext):
        pass


    # Enter a parse tree produced by rangesParser#bash_range.
    def enterBash_range(self, ctx:rangesParser.Bash_rangeContext):
        pass

    # Exit a parse tree produced by rangesParser#bash_range.
    def exitBash_range(self, ctx:rangesParser.Bash_rangeContext):
        pass


    # Enter a parse tree produced by rangesParser#dangr_range.
    def enterDangr_range(self, ctx:rangesParser.Dangr_rangeContext):
        pass

    # Exit a parse tree produced by rangesParser#dangr_range.
    def exitDangr_range(self, ctx:rangesParser.Dangr_rangeContext):
        pass


    # Enter a parse tree produced by rangesParser#python_range.
    def enterPython_range(self, ctx:rangesParser.Python_rangeContext):
        pass

    # Exit a parse tree produced by rangesParser#python_range.
    def exitPython_range(self, ctx:rangesParser.Python_rangeContext):
        pass


    # Enter a parse tree produced by rangesParser#bash_content.
    def enterBash_content(self, ctx:rangesParser.Bash_contentContext):
        pass

    # Exit a parse tree produced by rangesParser#bash_content.
    def exitBash_content(self, ctx:rangesParser.Bash_contentContext):
        pass


    # Enter a parse tree produced by rangesParser#py_content.
    def enterPy_content(self, ctx:rangesParser.Py_contentContext):
        pass

    # Exit a parse tree produced by rangesParser#py_content.
    def exitPy_content(self, ctx:rangesParser.Py_contentContext):
        pass


    # Enter a parse tree produced by rangesParser#anything.
    def enterAnything(self, ctx:rangesParser.AnythingContext):
        pass

    # Exit a parse tree produced by rangesParser#anything.
    def exitAnything(self, ctx:rangesParser.AnythingContext):
        pass


    # Enter a parse tree produced by rangesParser#symbol.
    def enterSymbol(self, ctx:rangesParser.SymbolContext):
        pass

    # Exit a parse tree produced by rangesParser#symbol.
    def exitSymbol(self, ctx:rangesParser.SymbolContext):
        pass



del rangesParser