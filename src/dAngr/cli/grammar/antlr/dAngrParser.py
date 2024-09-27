# Generated from /workspaces/dAngr/src/dAngr/cli/grammar/dAngr.g4 by ANTLR 4.13.1
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO


import re as rex

def serializedATN():
    return [
        4,1,69,520,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,1,0,1,0,1,0,3,0,62,8,0,1,0,1,0,1,0,1,0,5,0,68,
        8,0,10,0,12,0,71,9,0,3,0,73,8,0,1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,90,8,1,1,2,1,2,1,2,3,2,95,8,2,1,
        3,1,3,3,3,99,8,3,1,3,1,3,3,3,103,8,3,1,3,1,3,3,3,107,8,3,1,3,3,3,
        110,8,3,1,4,1,4,3,4,114,8,4,1,4,1,4,3,4,118,8,4,1,4,1,4,1,5,1,5,
        1,5,1,5,1,5,3,5,127,8,5,1,5,5,5,130,8,5,10,5,12,5,133,9,5,1,5,3,
        5,136,8,5,1,6,1,6,1,6,1,6,3,6,142,8,6,1,6,1,6,3,6,146,8,6,1,6,1,
        6,1,7,1,7,1,7,1,7,1,7,1,7,3,7,156,8,7,1,8,1,8,1,8,1,8,3,8,162,8,
        8,1,8,1,8,1,8,3,8,167,8,8,1,8,1,8,1,8,1,8,3,8,173,8,8,1,8,1,8,3,
        8,177,8,8,1,8,3,8,180,8,8,1,8,1,8,1,8,1,8,1,8,3,8,187,8,8,1,8,1,
        8,1,8,1,8,1,8,1,8,1,8,3,8,196,8,8,1,8,1,8,1,8,3,8,201,8,8,1,9,1,
        9,3,9,205,8,9,1,9,1,9,1,9,1,10,1,10,1,10,1,10,3,10,214,8,10,1,10,
        1,10,3,10,218,8,10,1,10,1,10,3,10,222,8,10,1,10,1,10,1,10,1,11,1,
        11,1,11,3,11,230,8,11,4,11,232,8,11,11,11,12,11,233,1,11,1,11,1,
        12,1,12,1,12,1,12,3,12,242,8,12,1,12,1,12,3,12,246,8,12,1,12,1,12,
        3,12,250,8,12,1,12,1,12,3,12,254,8,12,3,12,256,8,12,1,12,1,12,3,
        12,260,8,12,1,13,1,13,3,13,264,8,13,1,13,1,13,3,13,268,8,13,1,13,
        5,13,271,8,13,10,13,12,13,274,9,13,1,14,1,14,1,15,1,15,1,16,1,16,
        3,16,282,8,16,1,16,1,16,3,16,286,8,16,1,16,1,16,1,16,5,16,291,8,
        16,10,16,12,16,294,9,16,1,16,1,16,1,17,1,17,1,17,1,17,1,17,1,17,
        3,17,304,8,17,1,17,1,17,3,17,308,8,17,1,17,1,17,3,17,312,8,17,1,
        17,3,17,315,8,17,1,17,1,17,3,17,319,8,17,1,18,1,18,1,18,1,18,5,18,
        325,8,18,10,18,12,18,328,9,18,1,19,1,19,3,19,332,8,19,1,20,1,20,
        5,20,336,8,20,10,20,12,20,339,9,20,1,21,1,21,1,22,1,22,1,22,1,22,
        1,22,1,22,1,22,1,22,1,22,1,22,1,22,3,22,354,8,22,1,22,1,22,3,22,
        358,8,22,1,22,1,22,3,22,362,8,22,1,22,3,22,365,8,22,1,22,1,22,1,
        22,1,22,3,22,371,8,22,1,22,1,22,3,22,375,8,22,1,22,1,22,3,22,379,
        8,22,1,22,5,22,382,8,22,10,22,12,22,385,9,22,1,22,3,22,388,8,22,
        1,22,1,22,1,22,1,22,3,22,394,8,22,1,22,1,22,3,22,398,8,22,1,22,1,
        22,3,22,402,8,22,1,22,1,22,3,22,406,8,22,1,22,1,22,3,22,410,8,22,
        1,22,1,22,3,22,414,8,22,1,22,1,22,3,22,418,8,22,1,22,1,22,5,22,422,
        8,22,10,22,12,22,425,9,22,1,22,3,22,428,8,22,1,22,1,22,1,22,3,22,
        433,8,22,1,22,1,22,1,22,1,22,1,22,1,22,3,22,441,8,22,1,22,1,22,3,
        22,445,8,22,1,22,1,22,1,22,1,22,1,22,3,22,452,8,22,1,22,1,22,3,22,
        456,8,22,1,22,1,22,3,22,460,8,22,1,22,1,22,3,22,464,8,22,1,22,1,
        22,1,22,1,22,1,22,3,22,471,8,22,1,22,1,22,3,22,475,8,22,1,22,1,22,
        3,22,479,8,22,1,22,1,22,3,22,483,8,22,1,22,1,22,5,22,487,8,22,10,
        22,12,22,490,9,22,1,23,1,23,1,23,3,23,495,8,23,1,24,1,24,1,24,1,
        24,1,24,1,25,1,25,1,25,1,25,1,25,1,26,1,26,1,26,1,26,1,26,1,27,1,
        27,1,27,1,27,3,27,516,8,27,1,28,1,28,1,28,0,1,44,29,0,2,4,6,8,10,
        12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,
        56,0,7,2,0,10,10,62,62,3,0,48,52,54,61,67,67,1,0,18,20,2,0,16,16,
        65,65,3,0,14,14,16,16,65,65,1,0,13,14,2,0,12,12,29,66,599,0,72,1,
        0,0,0,2,89,1,0,0,0,4,94,1,0,0,0,6,109,1,0,0,0,8,111,1,0,0,0,10,135,
        1,0,0,0,12,137,1,0,0,0,14,155,1,0,0,0,16,200,1,0,0,0,18,202,1,0,
        0,0,20,209,1,0,0,0,22,226,1,0,0,0,24,259,1,0,0,0,26,261,1,0,0,0,
        28,275,1,0,0,0,30,277,1,0,0,0,32,279,1,0,0,0,34,318,1,0,0,0,36,320,
        1,0,0,0,38,331,1,0,0,0,40,333,1,0,0,0,42,340,1,0,0,0,44,432,1,0,
        0,0,46,494,1,0,0,0,48,496,1,0,0,0,50,501,1,0,0,0,52,506,1,0,0,0,
        54,515,1,0,0,0,56,517,1,0,0,0,58,61,7,0,0,0,59,60,5,12,0,0,60,62,
        3,40,20,0,61,59,1,0,0,0,61,62,1,0,0,0,62,63,1,0,0,0,63,73,5,11,0,
        0,64,68,5,11,0,0,65,68,3,2,1,0,66,68,3,20,10,0,67,64,1,0,0,0,67,
        65,1,0,0,0,67,66,1,0,0,0,68,71,1,0,0,0,69,67,1,0,0,0,69,70,1,0,0,
        0,70,73,1,0,0,0,71,69,1,0,0,0,72,58,1,0,0,0,72,69,1,0,0,0,73,74,
        1,0,0,0,74,75,5,0,0,1,75,1,1,0,0,0,76,90,3,16,8,0,77,78,3,10,5,0,
        78,79,5,11,0,0,79,90,1,0,0,0,80,81,3,8,4,0,81,82,5,11,0,0,82,90,
        1,0,0,0,83,84,3,4,2,0,84,85,5,11,0,0,85,90,1,0,0,0,86,87,3,14,7,
        0,87,88,5,11,0,0,88,90,1,0,0,0,89,76,1,0,0,0,89,77,1,0,0,0,89,80,
        1,0,0,0,89,83,1,0,0,0,89,86,1,0,0,0,90,3,1,0,0,0,91,95,3,44,22,0,
        92,95,3,46,23,0,93,95,3,6,3,0,94,91,1,0,0,0,94,92,1,0,0,0,94,93,
        1,0,0,0,95,5,1,0,0,0,96,106,3,44,22,0,97,99,5,12,0,0,98,97,1,0,0,
        0,98,99,1,0,0,0,99,100,1,0,0,0,100,102,3,30,15,0,101,103,5,12,0,
        0,102,101,1,0,0,0,102,103,1,0,0,0,103,104,1,0,0,0,104,105,3,6,3,
        0,105,107,1,0,0,0,106,98,1,0,0,0,106,107,1,0,0,0,107,110,1,0,0,0,
        108,110,3,46,23,0,109,96,1,0,0,0,109,108,1,0,0,0,110,7,1,0,0,0,111,
        113,3,44,22,0,112,114,5,12,0,0,113,112,1,0,0,0,113,114,1,0,0,0,114,
        115,1,0,0,0,115,117,5,53,0,0,116,118,5,12,0,0,117,116,1,0,0,0,117,
        118,1,0,0,0,118,119,1,0,0,0,119,120,3,4,2,0,120,9,1,0,0,0,121,131,
        3,40,20,0,122,126,5,12,0,0,123,124,3,40,20,0,124,125,5,53,0,0,125,
        127,1,0,0,0,126,123,1,0,0,0,126,127,1,0,0,0,127,128,1,0,0,0,128,
        130,3,4,2,0,129,122,1,0,0,0,130,133,1,0,0,0,131,129,1,0,0,0,131,
        132,1,0,0,0,132,136,1,0,0,0,133,131,1,0,0,0,134,136,3,12,6,0,135,
        121,1,0,0,0,135,134,1,0,0,0,136,11,1,0,0,0,137,138,5,1,0,0,138,139,
        5,12,0,0,139,141,3,44,22,0,140,142,5,12,0,0,141,140,1,0,0,0,141,
        142,1,0,0,0,142,143,1,0,0,0,143,145,3,30,15,0,144,146,5,12,0,0,145,
        144,1,0,0,0,145,146,1,0,0,0,146,147,1,0,0,0,147,148,3,4,2,0,148,
        13,1,0,0,0,149,150,5,31,0,0,150,156,3,32,16,0,151,152,5,32,0,0,152,
        156,3,10,5,0,153,154,5,33,0,0,154,156,3,36,18,0,155,149,1,0,0,0,
        155,151,1,0,0,0,155,153,1,0,0,0,156,15,1,0,0,0,157,158,5,4,0,0,158,
        159,5,12,0,0,159,161,3,28,14,0,160,162,5,12,0,0,161,160,1,0,0,0,
        161,162,1,0,0,0,162,163,1,0,0,0,163,164,5,34,0,0,164,166,3,22,11,
        0,165,167,3,18,9,0,166,165,1,0,0,0,166,167,1,0,0,0,167,201,1,0,0,
        0,168,169,5,6,0,0,169,170,5,12,0,0,170,179,3,40,20,0,171,173,5,12,
        0,0,172,171,1,0,0,0,172,173,1,0,0,0,173,174,1,0,0,0,174,176,5,36,
        0,0,175,177,5,12,0,0,176,175,1,0,0,0,176,177,1,0,0,0,177,178,1,0,
        0,0,178,180,3,40,20,0,179,172,1,0,0,0,179,180,1,0,0,0,180,181,1,
        0,0,0,181,182,5,12,0,0,182,183,5,7,0,0,183,184,5,12,0,0,184,186,
        3,24,12,0,185,187,5,12,0,0,186,185,1,0,0,0,186,187,1,0,0,0,187,188,
        1,0,0,0,188,189,5,34,0,0,189,190,3,22,11,0,190,201,1,0,0,0,191,192,
        5,8,0,0,192,193,5,12,0,0,193,195,3,28,14,0,194,196,5,12,0,0,195,
        194,1,0,0,0,195,196,1,0,0,0,196,197,1,0,0,0,197,198,5,34,0,0,198,
        199,3,22,11,0,199,201,1,0,0,0,200,157,1,0,0,0,200,168,1,0,0,0,200,
        191,1,0,0,0,201,17,1,0,0,0,202,204,5,5,0,0,203,205,5,12,0,0,204,
        203,1,0,0,0,204,205,1,0,0,0,205,206,1,0,0,0,206,207,5,34,0,0,207,
        208,3,22,11,0,208,19,1,0,0,0,209,210,5,3,0,0,210,211,5,12,0,0,211,
        213,3,40,20,0,212,214,5,12,0,0,213,212,1,0,0,0,213,214,1,0,0,0,214,
        215,1,0,0,0,215,217,5,29,0,0,216,218,3,26,13,0,217,216,1,0,0,0,217,
        218,1,0,0,0,218,219,1,0,0,0,219,221,5,30,0,0,220,222,5,12,0,0,221,
        220,1,0,0,0,221,222,1,0,0,0,222,223,1,0,0,0,223,224,5,34,0,0,224,
        225,3,22,11,0,225,21,1,0,0,0,226,231,5,68,0,0,227,229,3,2,1,0,228,
        230,5,11,0,0,229,228,1,0,0,0,229,230,1,0,0,0,230,232,1,0,0,0,231,
        227,1,0,0,0,232,233,1,0,0,0,233,231,1,0,0,0,233,234,1,0,0,0,234,
        235,1,0,0,0,235,236,5,69,0,0,236,23,1,0,0,0,237,260,3,44,22,0,238,
        239,5,2,0,0,239,241,5,29,0,0,240,242,5,12,0,0,241,240,1,0,0,0,241,
        242,1,0,0,0,242,243,1,0,0,0,243,245,3,42,21,0,244,246,5,12,0,0,245,
        244,1,0,0,0,245,246,1,0,0,0,246,255,1,0,0,0,247,249,5,36,0,0,248,
        250,5,12,0,0,249,248,1,0,0,0,249,250,1,0,0,0,250,251,1,0,0,0,251,
        253,3,42,21,0,252,254,5,12,0,0,253,252,1,0,0,0,253,254,1,0,0,0,254,
        256,1,0,0,0,255,247,1,0,0,0,255,256,1,0,0,0,256,257,1,0,0,0,257,
        258,5,30,0,0,258,260,1,0,0,0,259,237,1,0,0,0,259,238,1,0,0,0,260,
        25,1,0,0,0,261,272,3,40,20,0,262,264,5,12,0,0,263,262,1,0,0,0,263,
        264,1,0,0,0,264,265,1,0,0,0,265,267,5,36,0,0,266,268,5,12,0,0,267,
        266,1,0,0,0,267,268,1,0,0,0,268,269,1,0,0,0,269,271,3,40,20,0,270,
        263,1,0,0,0,271,274,1,0,0,0,272,270,1,0,0,0,272,273,1,0,0,0,273,
        27,1,0,0,0,274,272,1,0,0,0,275,276,3,4,2,0,276,29,1,0,0,0,277,278,
        7,1,0,0,278,31,1,0,0,0,279,281,3,40,20,0,280,282,5,12,0,0,281,280,
        1,0,0,0,281,282,1,0,0,0,282,283,1,0,0,0,283,285,5,29,0,0,284,286,
        5,12,0,0,285,284,1,0,0,0,285,286,1,0,0,0,286,292,1,0,0,0,287,291,
        3,46,23,0,288,291,3,54,27,0,289,291,3,34,17,0,290,287,1,0,0,0,290,
        288,1,0,0,0,290,289,1,0,0,0,291,294,1,0,0,0,292,290,1,0,0,0,292,
        293,1,0,0,0,293,295,1,0,0,0,294,292,1,0,0,0,295,296,5,30,0,0,296,
        33,1,0,0,0,297,298,7,2,0,0,298,299,5,40,0,0,299,319,3,40,20,0,300,
        301,5,21,0,0,301,303,5,42,0,0,302,304,5,12,0,0,303,302,1,0,0,0,303,
        304,1,0,0,0,304,305,1,0,0,0,305,314,3,42,21,0,306,308,5,12,0,0,307,
        306,1,0,0,0,307,308,1,0,0,0,308,309,1,0,0,0,309,311,5,28,0,0,310,
        312,5,12,0,0,311,310,1,0,0,0,311,312,1,0,0,0,312,313,1,0,0,0,313,
        315,5,14,0,0,314,307,1,0,0,0,314,315,1,0,0,0,315,316,1,0,0,0,316,
        317,5,43,0,0,317,319,1,0,0,0,318,297,1,0,0,0,318,300,1,0,0,0,319,
        35,1,0,0,0,320,326,3,40,20,0,321,325,3,46,23,0,322,325,3,54,27,0,
        323,325,3,34,17,0,324,321,1,0,0,0,324,322,1,0,0,0,324,323,1,0,0,
        0,325,328,1,0,0,0,326,324,1,0,0,0,326,327,1,0,0,0,327,37,1,0,0,0,
        328,326,1,0,0,0,329,332,3,40,20,0,330,332,3,42,21,0,331,329,1,0,
        0,0,331,330,1,0,0,0,332,39,1,0,0,0,333,337,7,3,0,0,334,336,7,4,0,
        0,335,334,1,0,0,0,336,339,1,0,0,0,337,335,1,0,0,0,337,338,1,0,0,
        0,338,41,1,0,0,0,339,337,1,0,0,0,340,341,7,5,0,0,341,43,1,0,0,0,
        342,343,6,22,-1,0,343,433,3,40,20,0,344,433,5,14,0,0,345,433,5,13,
        0,0,346,433,5,9,0,0,347,348,7,2,0,0,348,349,5,40,0,0,349,433,3,40,
        20,0,350,351,5,21,0,0,351,353,5,42,0,0,352,354,5,12,0,0,353,352,
        1,0,0,0,353,354,1,0,0,0,354,355,1,0,0,0,355,364,3,42,21,0,356,358,
        5,12,0,0,357,356,1,0,0,0,357,358,1,0,0,0,358,359,1,0,0,0,359,361,
        5,28,0,0,360,362,5,12,0,0,361,360,1,0,0,0,361,362,1,0,0,0,362,363,
        1,0,0,0,363,365,5,14,0,0,364,357,1,0,0,0,364,365,1,0,0,0,365,366,
        1,0,0,0,366,367,5,43,0,0,367,433,1,0,0,0,368,370,5,42,0,0,369,371,
        5,12,0,0,370,369,1,0,0,0,370,371,1,0,0,0,371,372,1,0,0,0,372,383,
        3,44,22,0,373,375,5,12,0,0,374,373,1,0,0,0,374,375,1,0,0,0,375,376,
        1,0,0,0,376,378,5,36,0,0,377,379,5,12,0,0,378,377,1,0,0,0,378,379,
        1,0,0,0,379,380,1,0,0,0,380,382,3,44,22,0,381,374,1,0,0,0,382,385,
        1,0,0,0,383,381,1,0,0,0,383,384,1,0,0,0,384,387,1,0,0,0,385,383,
        1,0,0,0,386,388,5,12,0,0,387,386,1,0,0,0,387,388,1,0,0,0,388,389,
        1,0,0,0,389,390,5,43,0,0,390,433,1,0,0,0,391,393,5,44,0,0,392,394,
        5,12,0,0,393,392,1,0,0,0,393,394,1,0,0,0,394,423,1,0,0,0,395,397,
        5,22,0,0,396,398,5,12,0,0,397,396,1,0,0,0,397,398,1,0,0,0,398,399,
        1,0,0,0,399,401,5,34,0,0,400,402,5,12,0,0,401,400,1,0,0,0,401,402,
        1,0,0,0,402,403,1,0,0,0,403,405,3,44,22,0,404,406,5,12,0,0,405,404,
        1,0,0,0,405,406,1,0,0,0,406,407,1,0,0,0,407,409,5,36,0,0,408,410,
        5,12,0,0,409,408,1,0,0,0,409,410,1,0,0,0,410,411,1,0,0,0,411,413,
        5,22,0,0,412,414,5,12,0,0,413,412,1,0,0,0,413,414,1,0,0,0,414,415,
        1,0,0,0,415,417,5,34,0,0,416,418,5,12,0,0,417,416,1,0,0,0,417,418,
        1,0,0,0,418,419,1,0,0,0,419,420,3,44,22,0,420,422,1,0,0,0,421,395,
        1,0,0,0,422,425,1,0,0,0,423,421,1,0,0,0,423,424,1,0,0,0,424,427,
        1,0,0,0,425,423,1,0,0,0,426,428,5,12,0,0,427,426,1,0,0,0,427,428,
        1,0,0,0,428,429,1,0,0,0,429,433,5,45,0,0,430,433,5,22,0,0,431,433,
        5,25,0,0,432,342,1,0,0,0,432,344,1,0,0,0,432,345,1,0,0,0,432,346,
        1,0,0,0,432,347,1,0,0,0,432,350,1,0,0,0,432,368,1,0,0,0,432,391,
        1,0,0,0,432,430,1,0,0,0,432,431,1,0,0,0,433,488,1,0,0,0,434,435,
        10,8,0,0,435,436,5,40,0,0,436,487,3,40,20,0,437,438,10,7,0,0,438,
        440,5,42,0,0,439,441,5,12,0,0,440,439,1,0,0,0,440,441,1,0,0,0,441,
        442,1,0,0,0,442,444,3,38,19,0,443,445,5,12,0,0,444,443,1,0,0,0,444,
        445,1,0,0,0,445,446,1,0,0,0,446,447,5,43,0,0,447,487,1,0,0,0,448,
        449,10,6,0,0,449,451,5,42,0,0,450,452,5,12,0,0,451,450,1,0,0,0,451,
        452,1,0,0,0,452,453,1,0,0,0,453,455,3,42,21,0,454,456,5,12,0,0,455,
        454,1,0,0,0,455,456,1,0,0,0,456,457,1,0,0,0,457,459,5,34,0,0,458,
        460,5,12,0,0,459,458,1,0,0,0,459,460,1,0,0,0,460,461,1,0,0,0,461,
        463,3,42,21,0,462,464,5,12,0,0,463,462,1,0,0,0,463,464,1,0,0,0,464,
        465,1,0,0,0,465,466,5,43,0,0,466,487,1,0,0,0,467,468,10,5,0,0,468,
        470,5,42,0,0,469,471,5,12,0,0,470,469,1,0,0,0,470,471,1,0,0,0,471,
        472,1,0,0,0,472,474,3,42,21,0,473,475,5,12,0,0,474,473,1,0,0,0,474,
        475,1,0,0,0,475,476,1,0,0,0,476,478,5,28,0,0,477,479,5,12,0,0,478,
        477,1,0,0,0,478,479,1,0,0,0,479,480,1,0,0,0,480,482,5,14,0,0,481,
        483,5,12,0,0,482,481,1,0,0,0,482,483,1,0,0,0,483,484,1,0,0,0,484,
        485,5,43,0,0,485,487,1,0,0,0,486,434,1,0,0,0,486,437,1,0,0,0,486,
        448,1,0,0,0,486,467,1,0,0,0,487,490,1,0,0,0,488,486,1,0,0,0,488,
        489,1,0,0,0,489,45,1,0,0,0,490,488,1,0,0,0,491,495,3,48,24,0,492,
        495,3,50,25,0,493,495,3,52,26,0,494,491,1,0,0,0,494,492,1,0,0,0,
        494,493,1,0,0,0,495,47,1,0,0,0,496,497,5,33,0,0,497,498,5,29,0,0,
        498,499,3,36,18,0,499,500,5,30,0,0,500,49,1,0,0,0,501,502,5,32,0,
        0,502,503,5,29,0,0,503,504,3,2,1,0,504,505,5,30,0,0,505,51,1,0,0,
        0,506,507,5,31,0,0,507,508,5,29,0,0,508,509,3,32,16,0,509,510,5,
        30,0,0,510,53,1,0,0,0,511,516,5,16,0,0,512,516,5,14,0,0,513,516,
        3,56,28,0,514,516,5,22,0,0,515,511,1,0,0,0,515,512,1,0,0,0,515,513,
        1,0,0,0,515,514,1,0,0,0,516,55,1,0,0,0,517,518,7,6,0,0,518,57,1,
        0,0,0,87,61,67,69,72,89,94,98,102,106,109,113,117,126,131,135,141,
        145,155,161,166,172,176,179,186,195,200,204,213,217,221,229,233,
        241,245,249,253,255,259,263,267,272,281,285,290,292,303,307,311,
        314,318,324,326,331,337,353,357,361,364,370,374,378,383,387,393,
        397,401,405,409,413,417,423,427,432,440,444,451,455,459,463,470,
        474,478,482,486,488,494,515
    ]

class dAngrParser ( Parser ):

    grammarFileName = "dAngr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'add_constraints'", "'range'", "'def'", 
                     "'if'", "'else'", "'for'", "'in'", "'while'", "<INVALID>", 
                     "'help'", "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'&sym'", "'&reg'", 
                     "'&vars'", "'&mem'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'->'", "'('", 
                     "')'", "'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", 
                     "'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", "'}'", 
                     "'^'", "'#'", "'%'", "'*'", "'+'", "'/'", "'**'", "'='", 
                     "'=='", "'!='", "'<'", "'>'", "'<='", "'>='", "'&&'", 
                     "'||'", "'?'", "'~'", "'`'", "'_'", "'-'" ]

    symbolicNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "DEF", "IF", 
                      "ELSE", "FOR", "IN", "WHILE", "BOOL", "HELP", "NEWLINE", 
                      "WS", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", 
                      "LETTER", "SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", 
                      "STRING", "ESCAPED_QUOTE", "ESCAPED_SINGLE_QUOTE", 
                      "BINARY_STRING", "SESC_SEQ", "ESC_SEQ", "ARROW", "LPAREN", 
                      "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", "SCOLON", 
                      "COMMA", "QUOTE", "SQUOTE", "AT", "DOT", "BAR", "BRA", 
                      "KET", "BRACE", "KETCE", "HAT", "HASH", "PERC", "TIMES", 
                      "ADD", "DIV", "POW", "ASSIGN", "EQ", "NEQ", "LT", 
                      "GT", "LE", "GE", "AND", "OR", "QMARK", "TILDE", "TICK", 
                      "UNDERSCORE", "DASH", "SUB", "INDENT", "DEDENT" ]

    RULE_script = 0
    RULE_statement = 1
    RULE_expression = 2
    RULE_expression_part = 3
    RULE_assignment = 4
    RULE_dangr_command = 5
    RULE_add_constraint = 6
    RULE_ext_command = 7
    RULE_control_flow = 8
    RULE_else_ = 9
    RULE_function_def = 10
    RULE_body = 11
    RULE_iterable = 12
    RULE_parameters = 13
    RULE_condition = 14
    RULE_operation = 15
    RULE_py_content = 16
    RULE_reference = 17
    RULE_bash_content = 18
    RULE_index = 19
    RULE_identifier = 20
    RULE_numeric = 21
    RULE_object = 22
    RULE_range = 23
    RULE_bash_range = 24
    RULE_dangr_range = 25
    RULE_python_range = 26
    RULE_anything = 27
    RULE_symbol = 28

    ruleNames =  [ "script", "statement", "expression", "expression_part", 
                   "assignment", "dangr_command", "add_constraint", "ext_command", 
                   "control_flow", "else_", "function_def", "body", "iterable", 
                   "parameters", "condition", "operation", "py_content", 
                   "reference", "bash_content", "index", "identifier", "numeric", 
                   "object", "range", "bash_range", "dangr_range", "python_range", 
                   "anything", "symbol" ]

    EOF = Token.EOF
    T__0=1
    T__1=2
    DEF=3
    IF=4
    ELSE=5
    FOR=6
    IN=7
    WHILE=8
    BOOL=9
    HELP=10
    NEWLINE=11
    WS=12
    HEX_NUMBERS=13
    NUMBERS=14
    NUMBER=15
    LETTERS=16
    LETTER=17
    SYM_DB=18
    REG_DB=19
    VARS_DB=20
    MEM_DB=21
    STRING=22
    ESCAPED_QUOTE=23
    ESCAPED_SINGLE_QUOTE=24
    BINARY_STRING=25
    SESC_SEQ=26
    ESC_SEQ=27
    ARROW=28
    LPAREN=29
    RPAREN=30
    BANG=31
    AMP=32
    DOLLAR=33
    COLON=34
    SCOLON=35
    COMMA=36
    QUOTE=37
    SQUOTE=38
    AT=39
    DOT=40
    BAR=41
    BRA=42
    KET=43
    BRACE=44
    KETCE=45
    HAT=46
    HASH=47
    PERC=48
    TIMES=49
    ADD=50
    DIV=51
    POW=52
    ASSIGN=53
    EQ=54
    NEQ=55
    LT=56
    GT=57
    LE=58
    GE=59
    AND=60
    OR=61
    QMARK=62
    TILDE=63
    TICK=64
    UNDERSCORE=65
    DASH=66
    SUB=67
    INDENT=68
    DEDENT=69

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class ScriptContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EOF(self):
            return self.getToken(dAngrParser.EOF, 0)

        def NEWLINE(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.NEWLINE)
            else:
                return self.getToken(dAngrParser.NEWLINE, i)

        def QMARK(self):
            return self.getToken(dAngrParser.QMARK, 0)

        def HELP(self):
            return self.getToken(dAngrParser.HELP, 0)

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def statement(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.StatementContext)
            else:
                return self.getTypedRuleContext(dAngrParser.StatementContext,i)


        def function_def(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Function_defContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Function_defContext,i)


        def getRuleIndex(self):
            return dAngrParser.RULE_script

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterScript" ):
                listener.enterScript(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitScript" ):
                listener.exitScript(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitScript" ):
                return visitor.visitScript(self)
            else:
                return visitor.visitChildren(self)




    def script(self):

        localctx = dAngrParser.ScriptContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_script)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 72
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [10, 62]:
                self.state = 58
                _la = self._input.LA(1)
                if not(_la==10 or _la==62):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 61
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 59
                    self.match(dAngrParser.WS)
                    self.state = 60
                    self.identifier()


                self.state = 63
                self.match(dAngrParser.NEWLINE)
                pass
            elif token in [-1, 1, 3, 4, 6, 8, 9, 11, 13, 14, 16, 18, 19, 20, 21, 22, 25, 31, 32, 33, 42, 44, 65]:
                self.state = 69
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while (((_la) & ~0x3f) == 0 and ((1 << _la) & 22005306714970) != 0) or _la==65:
                    self.state = 67
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [11]:
                        self.state = 64
                        self.match(dAngrParser.NEWLINE)
                        pass
                    elif token in [1, 4, 6, 8, 9, 13, 14, 16, 18, 19, 20, 21, 22, 25, 31, 32, 33, 42, 44, 65]:
                        self.state = 65
                        self.statement()
                        pass
                    elif token in [3]:
                        self.state = 66
                        self.function_def()
                        pass
                    else:
                        raise NoViableAltException(self)

                    self.state = 71
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                pass
            else:
                raise NoViableAltException(self)

            self.state = 74
            self.match(dAngrParser.EOF)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class StatementContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def control_flow(self):
            return self.getTypedRuleContext(dAngrParser.Control_flowContext,0)


        def dangr_command(self):
            return self.getTypedRuleContext(dAngrParser.Dangr_commandContext,0)


        def NEWLINE(self):
            return self.getToken(dAngrParser.NEWLINE, 0)

        def assignment(self):
            return self.getTypedRuleContext(dAngrParser.AssignmentContext,0)


        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def ext_command(self):
            return self.getTypedRuleContext(dAngrParser.Ext_commandContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_statement

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStatement" ):
                listener.enterStatement(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStatement" ):
                listener.exitStatement(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStatement" ):
                return visitor.visitStatement(self)
            else:
                return visitor.visitChildren(self)




    def statement(self):

        localctx = dAngrParser.StatementContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_statement)
        try:
            self.state = 89
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,4,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 76
                self.control_flow()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 77
                self.dangr_command()
                self.state = 78
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 80
                self.assignment()
                self.state = 81
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 83
                self.expression()
                self.state = 84
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 86
                self.ext_command()
                self.state = 87
                self.match(dAngrParser.NEWLINE)
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ExpressionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def range_(self):
            return self.getTypedRuleContext(dAngrParser.RangeContext,0)


        def expression_part(self):
            return self.getTypedRuleContext(dAngrParser.Expression_partContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_expression

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpression" ):
                listener.enterExpression(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpression" ):
                listener.exitExpression(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpression" ):
                return visitor.visitExpression(self)
            else:
                return visitor.visitChildren(self)




    def expression(self):

        localctx = dAngrParser.ExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_expression)
        try:
            self.state = 94
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 91
                self.object_(0)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 92
                self.range_()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 93
                self.expression_part()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Expression_partContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def operation(self):
            return self.getTypedRuleContext(dAngrParser.OperationContext,0)


        def expression_part(self):
            return self.getTypedRuleContext(dAngrParser.Expression_partContext,0)


        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def range_(self):
            return self.getTypedRuleContext(dAngrParser.RangeContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_expression_part

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpression_part" ):
                listener.enterExpression_part(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpression_part" ):
                listener.exitExpression_part(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpression_part" ):
                return visitor.visitExpression_part(self)
            else:
                return visitor.visitChildren(self)




    def expression_part(self):

        localctx = dAngrParser.Expression_partContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_expression_part)
        self._la = 0 # Token type
        try:
            self.state = 109
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [9, 13, 14, 16, 18, 19, 20, 21, 22, 25, 42, 44, 65]:
                self.enterOuterAlt(localctx, 1)
                self.state = 96
                self.object_(0)
                self.state = 106
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,8,self._ctx)
                if la_ == 1:
                    self.state = 98
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 97
                        self.match(dAngrParser.WS)


                    self.state = 100
                    self.operation()
                    self.state = 102
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 101
                        self.match(dAngrParser.WS)


                    self.state = 104
                    self.expression_part()


                pass
            elif token in [31, 32, 33]:
                self.enterOuterAlt(localctx, 2)
                self.state = 108
                self.range_()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class AssignmentContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def ASSIGN(self):
            return self.getToken(dAngrParser.ASSIGN, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def getRuleIndex(self):
            return dAngrParser.RULE_assignment

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAssignment" ):
                listener.enterAssignment(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAssignment" ):
                listener.exitAssignment(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAssignment" ):
                return visitor.visitAssignment(self)
            else:
                return visitor.visitChildren(self)




    def assignment(self):

        localctx = dAngrParser.AssignmentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_assignment)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 111
            self.object_(0)
            self.state = 113
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 112
                self.match(dAngrParser.WS)


            self.state = 115
            self.match(dAngrParser.ASSIGN)
            self.state = 117
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 116
                self.match(dAngrParser.WS)


            self.state = 119
            self.expression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Dangr_commandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IdentifierContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IdentifierContext,i)


        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def expression(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ExpressionContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ExpressionContext,i)


        def ASSIGN(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.ASSIGN)
            else:
                return self.getToken(dAngrParser.ASSIGN, i)

        def add_constraint(self):
            return self.getTypedRuleContext(dAngrParser.Add_constraintContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_dangr_command

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDangr_command" ):
                listener.enterDangr_command(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDangr_command" ):
                listener.exitDangr_command(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDangr_command" ):
                return visitor.visitDangr_command(self)
            else:
                return visitor.visitChildren(self)




    def dangr_command(self):

        localctx = dAngrParser.Dangr_commandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_dangr_command)
        self._la = 0 # Token type
        try:
            self.state = 135
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [16, 65]:
                self.enterOuterAlt(localctx, 1)
                self.state = 121
                self.identifier()
                self.state = 131
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==12:
                    self.state = 122
                    self.match(dAngrParser.WS)
                    self.state = 126
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,12,self._ctx)
                    if la_ == 1:
                        self.state = 123
                        self.identifier()
                        self.state = 124
                        self.match(dAngrParser.ASSIGN)


                    self.state = 128
                    self.expression()
                    self.state = 133
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                pass
            elif token in [1]:
                self.enterOuterAlt(localctx, 2)
                self.state = 134
                self.add_constraint()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Add_constraintContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def operation(self):
            return self.getTypedRuleContext(dAngrParser.OperationContext,0)


        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_add_constraint

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAdd_constraint" ):
                listener.enterAdd_constraint(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAdd_constraint" ):
                listener.exitAdd_constraint(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAdd_constraint" ):
                return visitor.visitAdd_constraint(self)
            else:
                return visitor.visitChildren(self)




    def add_constraint(self):

        localctx = dAngrParser.Add_constraintContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_add_constraint)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 137
            self.match(dAngrParser.T__0)
            self.state = 138
            self.match(dAngrParser.WS)
            self.state = 139
            self.object_(0)
            self.state = 141
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 140
                self.match(dAngrParser.WS)


            self.state = 143
            self.operation()
            self.state = 145
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 144
                self.match(dAngrParser.WS)


            self.state = 147
            self.expression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Ext_commandContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

        def py_content(self):
            return self.getTypedRuleContext(dAngrParser.Py_contentContext,0)


        def AMP(self):
            return self.getToken(dAngrParser.AMP, 0)

        def dangr_command(self):
            return self.getTypedRuleContext(dAngrParser.Dangr_commandContext,0)


        def DOLLAR(self):
            return self.getToken(dAngrParser.DOLLAR, 0)

        def bash_content(self):
            return self.getTypedRuleContext(dAngrParser.Bash_contentContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_ext_command

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExt_command" ):
                listener.enterExt_command(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExt_command" ):
                listener.exitExt_command(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExt_command" ):
                return visitor.visitExt_command(self)
            else:
                return visitor.visitChildren(self)




    def ext_command(self):

        localctx = dAngrParser.Ext_commandContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_ext_command)
        try:
            self.state = 155
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [31]:
                self.enterOuterAlt(localctx, 1)
                self.state = 149
                self.match(dAngrParser.BANG)
                self.state = 150
                self.py_content()
                pass
            elif token in [32]:
                self.enterOuterAlt(localctx, 2)
                self.state = 151
                self.match(dAngrParser.AMP)
                self.state = 152
                self.dangr_command()
                pass
            elif token in [33]:
                self.enterOuterAlt(localctx, 3)
                self.state = 153
                self.match(dAngrParser.DOLLAR)
                self.state = 154
                self.bash_content()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Control_flowContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def IF(self):
            return self.getToken(dAngrParser.IF, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def condition(self):
            return self.getTypedRuleContext(dAngrParser.ConditionContext,0)


        def COLON(self):
            return self.getToken(dAngrParser.COLON, 0)

        def body(self):
            return self.getTypedRuleContext(dAngrParser.BodyContext,0)


        def else_(self):
            return self.getTypedRuleContext(dAngrParser.Else_Context,0)


        def FOR(self):
            return self.getToken(dAngrParser.FOR, 0)

        def identifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IdentifierContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IdentifierContext,i)


        def IN(self):
            return self.getToken(dAngrParser.IN, 0)

        def iterable(self):
            return self.getTypedRuleContext(dAngrParser.IterableContext,0)


        def COMMA(self):
            return self.getToken(dAngrParser.COMMA, 0)

        def WHILE(self):
            return self.getToken(dAngrParser.WHILE, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_control_flow

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterControl_flow" ):
                listener.enterControl_flow(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitControl_flow" ):
                listener.exitControl_flow(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitControl_flow" ):
                return visitor.visitControl_flow(self)
            else:
                return visitor.visitChildren(self)




    def control_flow(self):

        localctx = dAngrParser.Control_flowContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_control_flow)
        self._la = 0 # Token type
        try:
            self.state = 200
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [4]:
                self.enterOuterAlt(localctx, 1)
                self.state = 157
                self.match(dAngrParser.IF)
                self.state = 158
                self.match(dAngrParser.WS)
                self.state = 159
                self.condition()
                self.state = 161
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 160
                    self.match(dAngrParser.WS)


                self.state = 163
                self.match(dAngrParser.COLON)
                self.state = 164
                self.body()
                self.state = 166
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==5:
                    self.state = 165
                    self.else_()


                pass
            elif token in [6]:
                self.enterOuterAlt(localctx, 2)
                self.state = 168
                self.match(dAngrParser.FOR)
                self.state = 169
                self.match(dAngrParser.WS)
                self.state = 170
                self.identifier()
                self.state = 179
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,22,self._ctx)
                if la_ == 1:
                    self.state = 172
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 171
                        self.match(dAngrParser.WS)


                    self.state = 174
                    self.match(dAngrParser.COMMA)
                    self.state = 176
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 175
                        self.match(dAngrParser.WS)


                    self.state = 178
                    self.identifier()


                self.state = 181
                self.match(dAngrParser.WS)
                self.state = 182
                self.match(dAngrParser.IN)
                self.state = 183
                self.match(dAngrParser.WS)
                self.state = 184
                self.iterable()
                self.state = 186
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 185
                    self.match(dAngrParser.WS)


                self.state = 188
                self.match(dAngrParser.COLON)
                self.state = 189
                self.body()
                pass
            elif token in [8]:
                self.enterOuterAlt(localctx, 3)
                self.state = 191
                self.match(dAngrParser.WHILE)
                self.state = 192
                self.match(dAngrParser.WS)
                self.state = 193
                self.condition()
                self.state = 195
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 194
                    self.match(dAngrParser.WS)


                self.state = 197
                self.match(dAngrParser.COLON)
                self.state = 198
                self.body()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Else_Context(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ELSE(self):
            return self.getToken(dAngrParser.ELSE, 0)

        def COLON(self):
            return self.getToken(dAngrParser.COLON, 0)

        def body(self):
            return self.getTypedRuleContext(dAngrParser.BodyContext,0)


        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_else_

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterElse_" ):
                listener.enterElse_(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitElse_" ):
                listener.exitElse_(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitElse_" ):
                return visitor.visitElse_(self)
            else:
                return visitor.visitChildren(self)




    def else_(self):

        localctx = dAngrParser.Else_Context(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_else_)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 202
            self.match(dAngrParser.ELSE)
            self.state = 204
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 203
                self.match(dAngrParser.WS)


            self.state = 206
            self.match(dAngrParser.COLON)
            self.state = 207
            self.body()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Function_defContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DEF(self):
            return self.getToken(dAngrParser.DEF, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def COLON(self):
            return self.getToken(dAngrParser.COLON, 0)

        def body(self):
            return self.getTypedRuleContext(dAngrParser.BodyContext,0)


        def parameters(self):
            return self.getTypedRuleContext(dAngrParser.ParametersContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_function_def

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFunction_def" ):
                listener.enterFunction_def(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFunction_def" ):
                listener.exitFunction_def(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFunction_def" ):
                return visitor.visitFunction_def(self)
            else:
                return visitor.visitChildren(self)




    def function_def(self):

        localctx = dAngrParser.Function_defContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_function_def)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 209
            self.match(dAngrParser.DEF)
            self.state = 210
            self.match(dAngrParser.WS)
            self.state = 211
            self.identifier()
            self.state = 213
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 212
                self.match(dAngrParser.WS)


            self.state = 215
            self.match(dAngrParser.LPAREN)
            self.state = 217
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16 or _la==65:
                self.state = 216
                self.parameters()


            self.state = 219
            self.match(dAngrParser.RPAREN)
            self.state = 221
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 220
                self.match(dAngrParser.WS)


            self.state = 223
            self.match(dAngrParser.COLON)
            self.state = 224
            self.body()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class BodyContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def INDENT(self):
            return self.getToken(dAngrParser.INDENT, 0)

        def DEDENT(self):
            return self.getToken(dAngrParser.DEDENT, 0)

        def statement(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.StatementContext)
            else:
                return self.getTypedRuleContext(dAngrParser.StatementContext,i)


        def NEWLINE(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.NEWLINE)
            else:
                return self.getToken(dAngrParser.NEWLINE, i)

        def getRuleIndex(self):
            return dAngrParser.RULE_body

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBody" ):
                listener.enterBody(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBody" ):
                listener.exitBody(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBody" ):
                return visitor.visitBody(self)
            else:
                return visitor.visitChildren(self)




    def body(self):

        localctx = dAngrParser.BodyContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_body)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 226
            self.match(dAngrParser.INDENT)
            self.state = 231 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 227
                self.statement()
                self.state = 229
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==11:
                    self.state = 228
                    self.match(dAngrParser.NEWLINE)


                self.state = 233 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 22005306712914) != 0) or _la==65):
                    break

            self.state = 235
            self.match(dAngrParser.DEDENT)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IterableContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def numeric(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.NumericContext)
            else:
                return self.getTypedRuleContext(dAngrParser.NumericContext,i)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def COMMA(self):
            return self.getToken(dAngrParser.COMMA, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_iterable

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIterable" ):
                listener.enterIterable(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIterable" ):
                listener.exitIterable(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIterable" ):
                return visitor.visitIterable(self)
            else:
                return visitor.visitChildren(self)




    def iterable(self):

        localctx = dAngrParser.IterableContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_iterable)
        self._la = 0 # Token type
        try:
            self.state = 259
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [9, 13, 14, 16, 18, 19, 20, 21, 22, 25, 42, 44, 65]:
                self.enterOuterAlt(localctx, 1)
                self.state = 237
                self.object_(0)
                pass
            elif token in [2]:
                self.enterOuterAlt(localctx, 2)
                self.state = 238
                self.match(dAngrParser.T__1)
                self.state = 239
                self.match(dAngrParser.LPAREN)
                self.state = 241
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 240
                    self.match(dAngrParser.WS)


                self.state = 243
                self.numeric()
                self.state = 245
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 244
                    self.match(dAngrParser.WS)


                self.state = 255
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==36:
                    self.state = 247
                    self.match(dAngrParser.COMMA)
                    self.state = 249
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 248
                        self.match(dAngrParser.WS)


                    self.state = 251
                    self.numeric()
                    self.state = 253
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 252
                        self.match(dAngrParser.WS)




                self.state = 257
                self.match(dAngrParser.RPAREN)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ParametersContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IdentifierContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IdentifierContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.COMMA)
            else:
                return self.getToken(dAngrParser.COMMA, i)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def getRuleIndex(self):
            return dAngrParser.RULE_parameters

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterParameters" ):
                listener.enterParameters(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitParameters" ):
                listener.exitParameters(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitParameters" ):
                return visitor.visitParameters(self)
            else:
                return visitor.visitChildren(self)




    def parameters(self):

        localctx = dAngrParser.ParametersContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_parameters)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 261
            self.identifier()
            self.state = 272
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==12 or _la==36:
                self.state = 263
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 262
                    self.match(dAngrParser.WS)


                self.state = 265
                self.match(dAngrParser.COMMA)
                self.state = 267
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 266
                    self.match(dAngrParser.WS)


                self.state = 269
                self.identifier()
                self.state = 274
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ConditionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_condition

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterCondition" ):
                listener.enterCondition(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitCondition" ):
                listener.exitCondition(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitCondition" ):
                return visitor.visitCondition(self)
            else:
                return visitor.visitChildren(self)




    def condition(self):

        localctx = dAngrParser.ConditionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 28, self.RULE_condition)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 275
            self.expression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class OperationContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ADD(self):
            return self.getToken(dAngrParser.ADD, 0)

        def SUB(self):
            return self.getToken(dAngrParser.SUB, 0)

        def TIMES(self):
            return self.getToken(dAngrParser.TIMES, 0)

        def DIV(self):
            return self.getToken(dAngrParser.DIV, 0)

        def PERC(self):
            return self.getToken(dAngrParser.PERC, 0)

        def POW(self):
            return self.getToken(dAngrParser.POW, 0)

        def EQ(self):
            return self.getToken(dAngrParser.EQ, 0)

        def NEQ(self):
            return self.getToken(dAngrParser.NEQ, 0)

        def GT(self):
            return self.getToken(dAngrParser.GT, 0)

        def LT(self):
            return self.getToken(dAngrParser.LT, 0)

        def LE(self):
            return self.getToken(dAngrParser.LE, 0)

        def GE(self):
            return self.getToken(dAngrParser.GE, 0)

        def AND(self):
            return self.getToken(dAngrParser.AND, 0)

        def OR(self):
            return self.getToken(dAngrParser.OR, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_operation

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterOperation" ):
                listener.enterOperation(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitOperation" ):
                listener.exitOperation(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitOperation" ):
                return visitor.visitOperation(self)
            else:
                return visitor.visitChildren(self)




    def operation(self):

        localctx = dAngrParser.OperationContext(self, self._ctx, self.state)
        self.enterRule(localctx, 30, self.RULE_operation)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 277
            _la = self._input.LA(1)
            if not(((((_la - 48)) & ~0x3f) == 0 and ((1 << (_la - 48)) & 540639) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Py_contentContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def range_(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.RangeContext)
            else:
                return self.getTypedRuleContext(dAngrParser.RangeContext,i)


        def anything(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.AnythingContext)
            else:
                return self.getTypedRuleContext(dAngrParser.AnythingContext,i)


        def reference(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ReferenceContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ReferenceContext,i)


        def getRuleIndex(self):
            return dAngrParser.RULE_py_content

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPy_content" ):
                listener.enterPy_content(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPy_content" ):
                listener.exitPy_content(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPy_content" ):
                return visitor.visitPy_content(self)
            else:
                return visitor.visitChildren(self)




    def py_content(self):

        localctx = dAngrParser.Py_contentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_py_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 279
            self.identifier()
            self.state = 281
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==12:
                self.state = 280
                self.match(dAngrParser.WS)


            self.state = 283
            self.match(dAngrParser.LPAREN)
            self.state = 285
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,42,self._ctx)
            if la_ == 1:
                self.state = 284
                self.match(dAngrParser.WS)


            self.state = 292
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,44,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 290
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,43,self._ctx)
                    if la_ == 1:
                        self.state = 287
                        self.range_()
                        pass

                    elif la_ == 2:
                        self.state = 288
                        self.anything()
                        pass

                    elif la_ == 3:
                        self.state = 289
                        self.reference()
                        pass

             
                self.state = 294
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,44,self._ctx)

            self.state = 295
            self.match(dAngrParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ReferenceContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def VARS_DB(self):
            return self.getToken(dAngrParser.VARS_DB, 0)

        def REG_DB(self):
            return self.getToken(dAngrParser.REG_DB, 0)

        def SYM_DB(self):
            return self.getToken(dAngrParser.SYM_DB, 0)

        def MEM_DB(self):
            return self.getToken(dAngrParser.MEM_DB, 0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)

        def numeric(self):
            return self.getTypedRuleContext(dAngrParser.NumericContext,0)


        def KET(self):
            return self.getToken(dAngrParser.KET, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def ARROW(self):
            return self.getToken(dAngrParser.ARROW, 0)

        def NUMBERS(self):
            return self.getToken(dAngrParser.NUMBERS, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_reference

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterReference" ):
                listener.enterReference(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitReference" ):
                listener.exitReference(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitReference" ):
                return visitor.visitReference(self)
            else:
                return visitor.visitChildren(self)




    def reference(self):

        localctx = dAngrParser.ReferenceContext(self, self._ctx, self.state)
        self.enterRule(localctx, 34, self.RULE_reference)
        self._la = 0 # Token type
        try:
            self.state = 318
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [18, 19, 20]:
                self.enterOuterAlt(localctx, 1)
                self.state = 297
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1835008) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 298
                self.match(dAngrParser.DOT)
                self.state = 299
                self.identifier()
                pass
            elif token in [21]:
                self.enterOuterAlt(localctx, 2)
                self.state = 300
                self.match(dAngrParser.MEM_DB)
                self.state = 301
                self.match(dAngrParser.BRA)
                self.state = 303
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 302
                    self.match(dAngrParser.WS)


                self.state = 305
                self.numeric()
                self.state = 314
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12 or _la==28:
                    self.state = 307
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 306
                        self.match(dAngrParser.WS)


                    self.state = 309
                    self.match(dAngrParser.ARROW)
                    self.state = 311
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 310
                        self.match(dAngrParser.WS)


                    self.state = 313
                    self.match(dAngrParser.NUMBERS)


                self.state = 316
                self.match(dAngrParser.KET)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Bash_contentContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def range_(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.RangeContext)
            else:
                return self.getTypedRuleContext(dAngrParser.RangeContext,i)


        def anything(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.AnythingContext)
            else:
                return self.getTypedRuleContext(dAngrParser.AnythingContext,i)


        def reference(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ReferenceContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ReferenceContext,i)


        def getRuleIndex(self):
            return dAngrParser.RULE_bash_content

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBash_content" ):
                listener.enterBash_content(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBash_content" ):
                listener.exitBash_content(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBash_content" ):
                return visitor.visitBash_content(self)
            else:
                return visitor.visitChildren(self)




    def bash_content(self):

        localctx = dAngrParser.Bash_contentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 36, self.RULE_bash_content)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 320
            self.identifier()
            self.state = 326
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,51,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 324
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,50,self._ctx)
                    if la_ == 1:
                        self.state = 321
                        self.range_()
                        pass

                    elif la_ == 2:
                        self.state = 322
                        self.anything()
                        pass

                    elif la_ == 3:
                        self.state = 323
                        self.reference()
                        pass

             
                self.state = 328
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,51,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IndexContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def numeric(self):
            return self.getTypedRuleContext(dAngrParser.NumericContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_index

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIndex" ):
                listener.enterIndex(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIndex" ):
                listener.exitIndex(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIndex" ):
                return visitor.visitIndex(self)
            else:
                return visitor.visitChildren(self)




    def index(self):

        localctx = dAngrParser.IndexContext(self, self._ctx, self.state)
        self.enterRule(localctx, 38, self.RULE_index)
        try:
            self.state = 331
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [16, 65]:
                self.enterOuterAlt(localctx, 1)
                self.state = 329
                self.identifier()
                pass
            elif token in [13, 14]:
                self.enterOuterAlt(localctx, 2)
                self.state = 330
                self.numeric()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IdentifierContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LETTERS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.LETTERS)
            else:
                return self.getToken(dAngrParser.LETTERS, i)

        def UNDERSCORE(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.UNDERSCORE)
            else:
                return self.getToken(dAngrParser.UNDERSCORE, i)

        def NUMBERS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.NUMBERS)
            else:
                return self.getToken(dAngrParser.NUMBERS, i)

        def getRuleIndex(self):
            return dAngrParser.RULE_identifier

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIdentifier" ):
                listener.enterIdentifier(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIdentifier" ):
                listener.exitIdentifier(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIdentifier" ):
                return visitor.visitIdentifier(self)
            else:
                return visitor.visitChildren(self)




    def identifier(self):

        localctx = dAngrParser.IdentifierContext(self, self._ctx, self.state)
        self.enterRule(localctx, 40, self.RULE_identifier)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 333
            _la = self._input.LA(1)
            if not(_la==16 or _la==65):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
            self.state = 337
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,53,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 334
                    _la = self._input.LA(1)
                    if not(((((_la - 14)) & ~0x3f) == 0 and ((1 << (_la - 14)) & 2251799813685253) != 0)):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume() 
                self.state = 339
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,53,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class NumericContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def NUMBERS(self):
            return self.getToken(dAngrParser.NUMBERS, 0)

        def HEX_NUMBERS(self):
            return self.getToken(dAngrParser.HEX_NUMBERS, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_numeric

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNumeric" ):
                listener.enterNumeric(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNumeric" ):
                listener.exitNumeric(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNumeric" ):
                return visitor.visitNumeric(self)
            else:
                return visitor.visitChildren(self)




    def numeric(self):

        localctx = dAngrParser.NumericContext(self, self._ctx, self.state)
        self.enterRule(localctx, 42, self.RULE_numeric)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 340
            _la = self._input.LA(1)
            if not(_la==13 or _la==14):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ObjectContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def NUMBERS(self):
            return self.getToken(dAngrParser.NUMBERS, 0)

        def HEX_NUMBERS(self):
            return self.getToken(dAngrParser.HEX_NUMBERS, 0)

        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

        def VARS_DB(self):
            return self.getToken(dAngrParser.VARS_DB, 0)

        def REG_DB(self):
            return self.getToken(dAngrParser.REG_DB, 0)

        def SYM_DB(self):
            return self.getToken(dAngrParser.SYM_DB, 0)

        def MEM_DB(self):
            return self.getToken(dAngrParser.MEM_DB, 0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)

        def numeric(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.NumericContext)
            else:
                return self.getTypedRuleContext(dAngrParser.NumericContext,i)


        def KET(self):
            return self.getToken(dAngrParser.KET, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def ARROW(self):
            return self.getToken(dAngrParser.ARROW, 0)

        def object_(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ObjectContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ObjectContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.COMMA)
            else:
                return self.getToken(dAngrParser.COMMA, i)

        def BRACE(self):
            return self.getToken(dAngrParser.BRACE, 0)

        def KETCE(self):
            return self.getToken(dAngrParser.KETCE, 0)

        def STRING(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.STRING)
            else:
                return self.getToken(dAngrParser.STRING, i)

        def COLON(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.COLON)
            else:
                return self.getToken(dAngrParser.COLON, i)

        def BINARY_STRING(self):
            return self.getToken(dAngrParser.BINARY_STRING, 0)

        def index(self):
            return self.getTypedRuleContext(dAngrParser.IndexContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_object

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterObject" ):
                listener.enterObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitObject" ):
                listener.exitObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitObject" ):
                return visitor.visitObject(self)
            else:
                return visitor.visitChildren(self)



    def object_(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = dAngrParser.ObjectContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 44
        self.enterRecursionRule(localctx, 44, self.RULE_object, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 432
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [16, 65]:
                self.state = 343
                self.identifier()
                pass
            elif token in [14]:
                self.state = 344
                self.match(dAngrParser.NUMBERS)
                pass
            elif token in [13]:
                self.state = 345
                self.match(dAngrParser.HEX_NUMBERS)
                pass
            elif token in [9]:
                self.state = 346
                self.match(dAngrParser.BOOL)
                pass
            elif token in [18, 19, 20]:
                self.state = 347
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 1835008) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 348
                self.match(dAngrParser.DOT)
                self.state = 349
                self.identifier()
                pass
            elif token in [21]:
                self.state = 350
                self.match(dAngrParser.MEM_DB)
                self.state = 351
                self.match(dAngrParser.BRA)
                self.state = 353
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 352
                    self.match(dAngrParser.WS)


                self.state = 355
                self.numeric()
                self.state = 364
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12 or _la==28:
                    self.state = 357
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 356
                        self.match(dAngrParser.WS)


                    self.state = 359
                    self.match(dAngrParser.ARROW)
                    self.state = 361
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 360
                        self.match(dAngrParser.WS)


                    self.state = 363
                    self.match(dAngrParser.NUMBERS)


                self.state = 366
                self.match(dAngrParser.KET)
                pass
            elif token in [42]:
                self.state = 368
                self.match(dAngrParser.BRA)
                self.state = 370
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 369
                    self.match(dAngrParser.WS)


                self.state = 372
                self.object_(0)
                self.state = 383
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,61,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 374
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 373
                            self.match(dAngrParser.WS)


                        self.state = 376
                        self.match(dAngrParser.COMMA)
                        self.state = 378
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 377
                            self.match(dAngrParser.WS)


                        self.state = 380
                        self.object_(0) 
                    self.state = 385
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,61,self._ctx)

                self.state = 387
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 386
                    self.match(dAngrParser.WS)


                self.state = 389
                self.match(dAngrParser.KET)
                pass
            elif token in [44]:
                self.state = 391
                self.match(dAngrParser.BRACE)
                self.state = 393
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,63,self._ctx)
                if la_ == 1:
                    self.state = 392
                    self.match(dAngrParser.WS)


                self.state = 423
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==22:
                    self.state = 395
                    self.match(dAngrParser.STRING)
                    self.state = 397
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 396
                        self.match(dAngrParser.WS)


                    self.state = 399
                    self.match(dAngrParser.COLON)
                    self.state = 401
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 400
                        self.match(dAngrParser.WS)


                    self.state = 403
                    self.object_(0)

                    self.state = 405
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 404
                        self.match(dAngrParser.WS)


                    self.state = 407
                    self.match(dAngrParser.COMMA)
                    self.state = 409
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 408
                        self.match(dAngrParser.WS)


                    self.state = 411
                    self.match(dAngrParser.STRING)
                    self.state = 413
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 412
                        self.match(dAngrParser.WS)


                    self.state = 415
                    self.match(dAngrParser.COLON)
                    self.state = 417
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==12:
                        self.state = 416
                        self.match(dAngrParser.WS)


                    self.state = 419
                    self.object_(0)
                    self.state = 425
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 427
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==12:
                    self.state = 426
                    self.match(dAngrParser.WS)


                self.state = 429
                self.match(dAngrParser.KETCE)
                pass
            elif token in [22]:
                self.state = 430
                self.match(dAngrParser.STRING)
                pass
            elif token in [25]:
                self.state = 431
                self.match(dAngrParser.BINARY_STRING)
                pass
            else:
                raise NoViableAltException(self)

            self._ctx.stop = self._input.LT(-1)
            self.state = 488
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,84,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 486
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,83,self._ctx)
                    if la_ == 1:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 434
                        if not self.precpred(self._ctx, 8):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 8)")
                        self.state = 435
                        self.match(dAngrParser.DOT)
                        self.state = 436
                        self.identifier()
                        pass

                    elif la_ == 2:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 437
                        if not self.precpred(self._ctx, 7):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 7)")
                        self.state = 438
                        self.match(dAngrParser.BRA)
                        self.state = 440
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 439
                            self.match(dAngrParser.WS)


                        self.state = 442
                        self.index()
                        self.state = 444
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 443
                            self.match(dAngrParser.WS)


                        self.state = 446
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 3:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 448
                        if not self.precpred(self._ctx, 6):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                        self.state = 449
                        self.match(dAngrParser.BRA)
                        self.state = 451
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 450
                            self.match(dAngrParser.WS)


                        self.state = 453
                        self.numeric()
                        self.state = 455
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 454
                            self.match(dAngrParser.WS)


                        self.state = 457
                        self.match(dAngrParser.COLON)
                        self.state = 459
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 458
                            self.match(dAngrParser.WS)


                        self.state = 461
                        self.numeric()
                        self.state = 463
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 462
                            self.match(dAngrParser.WS)


                        self.state = 465
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 4:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 467
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 468
                        self.match(dAngrParser.BRA)
                        self.state = 470
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 469
                            self.match(dAngrParser.WS)


                        self.state = 472
                        self.numeric()
                        self.state = 474
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 473
                            self.match(dAngrParser.WS)


                        self.state = 476
                        self.match(dAngrParser.ARROW)
                        self.state = 478
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 477
                            self.match(dAngrParser.WS)


                        self.state = 480
                        self.match(dAngrParser.NUMBERS)
                        self.state = 482
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==12:
                            self.state = 481
                            self.match(dAngrParser.WS)


                        self.state = 484
                        self.match(dAngrParser.KET)
                        pass

             
                self.state = 490
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,84,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class RangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def bash_range(self):
            return self.getTypedRuleContext(dAngrParser.Bash_rangeContext,0)


        def dangr_range(self):
            return self.getTypedRuleContext(dAngrParser.Dangr_rangeContext,0)


        def python_range(self):
            return self.getTypedRuleContext(dAngrParser.Python_rangeContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRange" ):
                listener.enterRange(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRange" ):
                listener.exitRange(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitRange" ):
                return visitor.visitRange(self)
            else:
                return visitor.visitChildren(self)




    def range_(self):

        localctx = dAngrParser.RangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 46, self.RULE_range)
        try:
            self.state = 494
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [33]:
                self.enterOuterAlt(localctx, 1)
                self.state = 491
                self.bash_range()
                pass
            elif token in [32]:
                self.enterOuterAlt(localctx, 2)
                self.state = 492
                self.dangr_range()
                pass
            elif token in [31]:
                self.enterOuterAlt(localctx, 3)
                self.state = 493
                self.python_range()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Bash_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def DOLLAR(self):
            return self.getToken(dAngrParser.DOLLAR, 0)

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def bash_content(self):
            return self.getTypedRuleContext(dAngrParser.Bash_contentContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_bash_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBash_range" ):
                listener.enterBash_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBash_range" ):
                listener.exitBash_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBash_range" ):
                return visitor.visitBash_range(self)
            else:
                return visitor.visitChildren(self)




    def bash_range(self):

        localctx = dAngrParser.Bash_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 48, self.RULE_bash_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 496
            self.match(dAngrParser.DOLLAR)
            self.state = 497
            self.match(dAngrParser.LPAREN)
            self.state = 498
            self.bash_content()
            self.state = 499
            self.match(dAngrParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Dangr_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def AMP(self):
            return self.getToken(dAngrParser.AMP, 0)

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def statement(self):
            return self.getTypedRuleContext(dAngrParser.StatementContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_dangr_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDangr_range" ):
                listener.enterDangr_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDangr_range" ):
                listener.exitDangr_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDangr_range" ):
                return visitor.visitDangr_range(self)
            else:
                return visitor.visitChildren(self)




    def dangr_range(self):

        localctx = dAngrParser.Dangr_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 50, self.RULE_dangr_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 501
            self.match(dAngrParser.AMP)
            self.state = 502
            self.match(dAngrParser.LPAREN)
            self.state = 503
            self.statement()
            self.state = 504
            self.match(dAngrParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Python_rangeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def py_content(self):
            return self.getTypedRuleContext(dAngrParser.Py_contentContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_python_range

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPython_range" ):
                listener.enterPython_range(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPython_range" ):
                listener.exitPython_range(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPython_range" ):
                return visitor.visitPython_range(self)
            else:
                return visitor.visitChildren(self)




    def python_range(self):

        localctx = dAngrParser.Python_rangeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 52, self.RULE_python_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 506
            self.match(dAngrParser.BANG)
            self.state = 507
            self.match(dAngrParser.LPAREN)
            self.state = 508
            self.py_content()
            self.state = 509
            self.match(dAngrParser.RPAREN)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class AnythingContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def LETTERS(self):
            return self.getToken(dAngrParser.LETTERS, 0)

        def NUMBERS(self):
            return self.getToken(dAngrParser.NUMBERS, 0)

        def symbol(self):
            return self.getTypedRuleContext(dAngrParser.SymbolContext,0)


        def STRING(self):
            return self.getToken(dAngrParser.STRING, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_anything

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAnything" ):
                listener.enterAnything(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAnything" ):
                listener.exitAnything(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitAnything" ):
                return visitor.visitAnything(self)
            else:
                return visitor.visitChildren(self)




    def anything(self):

        localctx = dAngrParser.AnythingContext(self, self._ctx, self.state)
        self.enterRule(localctx, 54, self.RULE_anything)
        try:
            self.state = 515
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [16]:
                self.enterOuterAlt(localctx, 1)
                self.state = 511
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [14]:
                self.enterOuterAlt(localctx, 2)
                self.state = 512
                self.match(dAngrParser.NUMBERS)
                pass
            elif token in [12, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66]:
                self.enterOuterAlt(localctx, 3)
                self.state = 513
                self.symbol()
                pass
            elif token in [22]:
                self.enterOuterAlt(localctx, 4)
                self.state = 514
                self.match(dAngrParser.STRING)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SymbolContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

        def AMP(self):
            return self.getToken(dAngrParser.AMP, 0)

        def DOLLAR(self):
            return self.getToken(dAngrParser.DOLLAR, 0)

        def COLON(self):
            return self.getToken(dAngrParser.COLON, 0)

        def SCOLON(self):
            return self.getToken(dAngrParser.SCOLON, 0)

        def COMMA(self):
            return self.getToken(dAngrParser.COMMA, 0)

        def QUOTE(self):
            return self.getToken(dAngrParser.QUOTE, 0)

        def SQUOTE(self):
            return self.getToken(dAngrParser.SQUOTE, 0)

        def AT(self):
            return self.getToken(dAngrParser.AT, 0)

        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

        def BAR(self):
            return self.getToken(dAngrParser.BAR, 0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)

        def KET(self):
            return self.getToken(dAngrParser.KET, 0)

        def BRACE(self):
            return self.getToken(dAngrParser.BRACE, 0)

        def KETCE(self):
            return self.getToken(dAngrParser.KETCE, 0)

        def HAT(self):
            return self.getToken(dAngrParser.HAT, 0)

        def HASH(self):
            return self.getToken(dAngrParser.HASH, 0)

        def PERC(self):
            return self.getToken(dAngrParser.PERC, 0)

        def TIMES(self):
            return self.getToken(dAngrParser.TIMES, 0)

        def ADD(self):
            return self.getToken(dAngrParser.ADD, 0)

        def DIV(self):
            return self.getToken(dAngrParser.DIV, 0)

        def POW(self):
            return self.getToken(dAngrParser.POW, 0)

        def ASSIGN(self):
            return self.getToken(dAngrParser.ASSIGN, 0)

        def EQ(self):
            return self.getToken(dAngrParser.EQ, 0)

        def NEQ(self):
            return self.getToken(dAngrParser.NEQ, 0)

        def LT(self):
            return self.getToken(dAngrParser.LT, 0)

        def GT(self):
            return self.getToken(dAngrParser.GT, 0)

        def LE(self):
            return self.getToken(dAngrParser.LE, 0)

        def GE(self):
            return self.getToken(dAngrParser.GE, 0)

        def AND(self):
            return self.getToken(dAngrParser.AND, 0)

        def OR(self):
            return self.getToken(dAngrParser.OR, 0)

        def QMARK(self):
            return self.getToken(dAngrParser.QMARK, 0)

        def TILDE(self):
            return self.getToken(dAngrParser.TILDE, 0)

        def TICK(self):
            return self.getToken(dAngrParser.TICK, 0)

        def UNDERSCORE(self):
            return self.getToken(dAngrParser.UNDERSCORE, 0)

        def DASH(self):
            return self.getToken(dAngrParser.DASH, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_symbol

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSymbol" ):
                listener.enterSymbol(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSymbol" ):
                listener.exitSymbol(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSymbol" ):
                return visitor.visitSymbol(self)
            else:
                return visitor.visitChildren(self)




    def symbol(self):

        localctx = dAngrParser.SymbolContext(self, self._ctx, self.state)
        self.enterRule(localctx, 56, self.RULE_symbol)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 517
            _la = self._input.LA(1)
            if not(((((_la - 12)) & ~0x3f) == 0 and ((1 << (_la - 12)) & 36028797018832897) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx



    def sempred(self, localctx:RuleContext, ruleIndex:int, predIndex:int):
        if self._predicates == None:
            self._predicates = dict()
        self._predicates[22] = self.object_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def object_sempred(self, localctx:ObjectContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 8)
         

            if predIndex == 1:
                return self.precpred(self._ctx, 7)
         

            if predIndex == 2:
                return self.precpred(self._ctx, 6)
         

            if predIndex == 3:
                return self.precpred(self._ctx, 5)
         




