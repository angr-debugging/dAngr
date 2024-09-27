# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/ranges.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .rangesParser import rangesParser
else:
    from rangesParser import rangesParser

# This class defines a complete generic visitor for a parse tree produced by rangesParser.

class rangesVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by rangesParser#statement.
    def visitStatement(self, ctx:rangesParser.StatementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#range.
    def visitRange(self, ctx:rangesParser.RangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#bash_range.
    def visitBash_range(self, ctx:rangesParser.Bash_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#dangr_range.
    def visitDangr_range(self, ctx:rangesParser.Dangr_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#python_range.
    def visitPython_range(self, ctx:rangesParser.Python_rangeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#bash_content.
    def visitBash_content(self, ctx:rangesParser.Bash_contentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#py_content.
    def visitPy_content(self, ctx:rangesParser.Py_contentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#anything.
    def visitAnything(self, ctx:rangesParser.AnythingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by rangesParser#symbol.
    def visitSymbol(self, ctx:rangesParser.SymbolContext):
        return self.visitChildren(ctx)



del rangesParser