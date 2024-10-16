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
        4,1,73,556,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,1,0,1,0,1,0,3,0,66,8,0,1,
        0,1,0,1,0,1,0,5,0,72,8,0,10,0,12,0,75,9,0,3,0,77,8,0,1,0,1,0,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,94,8,1,1,2,1,
        2,1,2,1,2,1,2,3,2,101,8,2,1,2,5,2,104,8,2,10,2,12,2,107,9,2,1,2,
        1,2,3,2,111,8,2,1,3,1,3,3,3,115,8,3,1,3,1,3,3,3,119,8,3,1,3,1,3,
        3,3,123,8,3,1,3,1,3,3,3,127,8,3,1,3,1,3,3,3,131,8,3,1,3,1,3,1,4,
        1,4,3,4,137,8,4,1,4,1,4,3,4,141,8,4,1,4,1,4,1,4,1,4,1,4,1,4,3,4,
        149,8,4,1,4,1,4,3,4,153,8,4,1,4,1,4,3,4,157,8,4,3,4,159,8,4,1,5,
        1,5,3,5,163,8,5,1,5,3,5,166,8,5,1,5,1,5,3,5,170,8,5,1,5,1,5,1,6,
        1,6,1,6,1,6,1,7,1,7,1,7,1,7,1,7,1,7,3,7,184,8,7,1,8,1,8,1,8,1,8,
        3,8,190,8,8,1,8,1,8,1,8,3,8,195,8,8,1,8,1,8,1,8,1,8,3,8,201,8,8,
        1,8,1,8,3,8,205,8,8,1,8,3,8,208,8,8,1,8,1,8,1,8,1,8,1,8,3,8,215,
        8,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,3,8,224,8,8,1,8,1,8,1,8,3,8,229,
        8,8,1,9,1,9,3,9,233,8,9,1,9,1,9,1,9,1,10,1,10,1,10,1,10,3,10,242,
        8,10,1,10,1,10,3,10,246,8,10,1,10,1,10,3,10,250,8,10,1,10,1,10,1,
        10,1,11,1,11,1,11,3,11,258,8,11,4,11,260,8,11,11,11,12,11,261,1,
        11,1,11,1,12,1,12,1,12,1,12,3,12,270,8,12,1,12,1,12,3,12,274,8,12,
        1,12,1,12,3,12,278,8,12,1,12,1,12,3,12,282,8,12,3,12,284,8,12,1,
        12,1,12,3,12,288,8,12,1,13,1,13,3,13,292,8,13,1,13,1,13,3,13,296,
        8,13,1,13,5,13,299,8,13,10,13,12,13,302,9,13,1,14,1,14,1,15,1,15,
        1,16,1,16,3,16,310,8,16,1,16,1,16,3,16,314,8,16,1,16,5,16,317,8,
        16,10,16,12,16,320,9,16,1,16,1,16,1,17,1,17,1,17,1,17,1,17,1,17,
        1,17,4,17,331,8,17,11,17,12,17,332,1,18,1,18,1,18,1,18,1,18,1,18,
        1,18,3,18,342,8,18,1,18,1,18,3,18,346,8,18,1,18,1,18,3,18,350,8,
        18,1,18,3,18,353,8,18,1,18,1,18,3,18,357,8,18,1,19,1,19,1,19,1,19,
        5,19,363,8,19,10,19,12,19,366,9,19,1,20,1,20,3,20,370,8,20,1,21,
        1,21,1,21,1,21,1,21,3,21,377,8,21,1,21,1,21,1,21,1,21,5,21,383,8,
        21,10,21,12,21,386,9,21,1,22,1,22,1,23,1,23,1,23,3,23,393,8,23,1,
        23,1,23,1,23,1,23,1,23,1,23,3,23,401,8,23,1,23,1,23,3,23,405,8,23,
        1,23,1,23,3,23,409,8,23,1,23,5,23,412,8,23,10,23,12,23,415,9,23,
        1,23,3,23,418,8,23,1,23,1,23,1,23,1,23,3,23,424,8,23,1,23,1,23,3,
        23,428,8,23,1,23,1,23,3,23,432,8,23,1,23,1,23,3,23,436,8,23,1,23,
        1,23,3,23,440,8,23,1,23,1,23,3,23,444,8,23,1,23,1,23,3,23,448,8,
        23,1,23,1,23,5,23,452,8,23,10,23,12,23,455,9,23,1,23,3,23,458,8,
        23,1,23,1,23,1,23,3,23,463,8,23,1,23,1,23,1,23,1,23,1,23,1,23,3,
        23,471,8,23,1,23,1,23,3,23,475,8,23,1,23,1,23,1,23,1,23,1,23,3,23,
        482,8,23,1,23,1,23,3,23,486,8,23,1,23,1,23,3,23,490,8,23,1,23,1,
        23,3,23,494,8,23,1,23,1,23,1,23,1,23,1,23,3,23,501,8,23,1,23,1,23,
        3,23,505,8,23,1,23,1,23,3,23,509,8,23,1,23,1,23,3,23,513,8,23,1,
        23,1,23,5,23,517,8,23,10,23,12,23,520,9,23,1,24,1,24,1,25,1,25,1,
        25,3,25,527,8,25,1,26,1,26,1,26,1,26,1,26,1,27,1,27,1,27,1,27,1,
        27,1,28,1,28,1,28,1,28,1,28,1,29,1,29,1,29,1,29,1,29,1,29,1,29,1,
        29,3,29,552,8,29,1,30,1,30,1,30,0,1,46,31,0,2,4,6,8,10,12,14,16,
        18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,
        0,7,2,0,13,13,66,66,3,0,52,56,58,65,70,70,1,0,21,23,1,0,16,17,2,
        0,54,54,71,71,1,0,2,13,2,0,15,15,35,70,645,0,76,1,0,0,0,2,93,1,0,
        0,0,4,110,1,0,0,0,6,112,1,0,0,0,8,158,1,0,0,0,10,162,1,0,0,0,12,
        173,1,0,0,0,14,183,1,0,0,0,16,228,1,0,0,0,18,230,1,0,0,0,20,237,
        1,0,0,0,22,254,1,0,0,0,24,287,1,0,0,0,26,289,1,0,0,0,28,303,1,0,
        0,0,30,305,1,0,0,0,32,307,1,0,0,0,34,330,1,0,0,0,36,356,1,0,0,0,
        38,358,1,0,0,0,40,369,1,0,0,0,42,376,1,0,0,0,44,387,1,0,0,0,46,462,
        1,0,0,0,48,521,1,0,0,0,50,526,1,0,0,0,52,528,1,0,0,0,54,533,1,0,
        0,0,56,538,1,0,0,0,58,551,1,0,0,0,60,553,1,0,0,0,62,65,7,0,0,0,63,
        64,5,15,0,0,64,66,3,42,21,0,65,63,1,0,0,0,65,66,1,0,0,0,66,67,1,
        0,0,0,67,77,5,14,0,0,68,72,5,14,0,0,69,72,3,2,1,0,70,72,3,20,10,
        0,71,68,1,0,0,0,71,69,1,0,0,0,71,70,1,0,0,0,72,75,1,0,0,0,73,71,
        1,0,0,0,73,74,1,0,0,0,74,77,1,0,0,0,75,73,1,0,0,0,76,62,1,0,0,0,
        76,73,1,0,0,0,77,78,1,0,0,0,78,79,5,0,0,1,79,1,1,0,0,0,80,94,3,16,
        8,0,81,82,3,10,5,0,82,83,5,14,0,0,83,94,1,0,0,0,84,85,3,4,2,0,85,
        86,5,14,0,0,86,94,1,0,0,0,87,88,3,12,6,0,88,89,5,14,0,0,89,94,1,
        0,0,0,90,91,3,14,7,0,91,92,5,14,0,0,92,94,1,0,0,0,93,80,1,0,0,0,
        93,81,1,0,0,0,93,84,1,0,0,0,93,87,1,0,0,0,93,90,1,0,0,0,94,3,1,0,
        0,0,95,105,3,42,21,0,96,100,5,15,0,0,97,98,3,42,21,0,98,99,5,57,
        0,0,99,101,1,0,0,0,100,97,1,0,0,0,100,101,1,0,0,0,101,102,1,0,0,
        0,102,104,3,8,4,0,103,96,1,0,0,0,104,107,1,0,0,0,105,103,1,0,0,0,
        105,106,1,0,0,0,106,111,1,0,0,0,107,105,1,0,0,0,108,111,3,6,3,0,
        109,111,3,8,4,0,110,95,1,0,0,0,110,108,1,0,0,0,110,109,1,0,0,0,111,
        5,1,0,0,0,112,114,5,3,0,0,113,115,5,15,0,0,114,113,1,0,0,0,114,115,
        1,0,0,0,115,116,1,0,0,0,116,118,3,28,14,0,117,119,5,15,0,0,118,117,
        1,0,0,0,118,119,1,0,0,0,119,120,1,0,0,0,120,122,5,4,0,0,121,123,
        5,15,0,0,122,121,1,0,0,0,122,123,1,0,0,0,123,124,1,0,0,0,124,126,
        3,8,4,0,125,127,5,15,0,0,126,125,1,0,0,0,126,127,1,0,0,0,127,128,
        1,0,0,0,128,130,5,5,0,0,129,131,5,15,0,0,130,129,1,0,0,0,130,131,
        1,0,0,0,131,132,1,0,0,0,132,133,3,8,4,0,133,7,1,0,0,0,134,136,5,
        33,0,0,135,137,5,15,0,0,136,135,1,0,0,0,136,137,1,0,0,0,137,138,
        1,0,0,0,138,140,3,4,2,0,139,141,5,15,0,0,140,139,1,0,0,0,140,141,
        1,0,0,0,141,142,1,0,0,0,142,143,5,34,0,0,143,159,1,0,0,0,144,159,
        3,50,25,0,145,159,3,36,18,0,146,156,3,46,23,0,147,149,5,15,0,0,148,
        147,1,0,0,0,148,149,1,0,0,0,149,150,1,0,0,0,150,152,3,30,15,0,151,
        153,5,15,0,0,152,151,1,0,0,0,152,153,1,0,0,0,153,154,1,0,0,0,154,
        155,3,4,2,0,155,157,1,0,0,0,156,148,1,0,0,0,156,157,1,0,0,0,157,
        159,1,0,0,0,158,134,1,0,0,0,158,144,1,0,0,0,158,145,1,0,0,0,158,
        146,1,0,0,0,159,9,1,0,0,0,160,163,3,12,6,0,161,163,3,46,23,0,162,
        160,1,0,0,0,162,161,1,0,0,0,163,165,1,0,0,0,164,166,5,15,0,0,165,
        164,1,0,0,0,165,166,1,0,0,0,166,167,1,0,0,0,167,169,5,57,0,0,168,
        170,5,15,0,0,169,168,1,0,0,0,169,170,1,0,0,0,170,171,1,0,0,0,171,
        172,3,4,2,0,172,11,1,0,0,0,173,174,5,2,0,0,174,175,5,15,0,0,175,
        176,3,42,21,0,176,13,1,0,0,0,177,178,5,35,0,0,178,184,3,32,16,0,
        179,180,5,36,0,0,180,184,3,4,2,0,181,182,5,37,0,0,182,184,3,38,19,
        0,183,177,1,0,0,0,183,179,1,0,0,0,183,181,1,0,0,0,184,15,1,0,0,0,
        185,186,5,7,0,0,186,187,5,15,0,0,187,189,3,28,14,0,188,190,5,15,
        0,0,189,188,1,0,0,0,189,190,1,0,0,0,190,191,1,0,0,0,191,192,5,38,
        0,0,192,194,3,22,11,0,193,195,3,18,9,0,194,193,1,0,0,0,194,195,1,
        0,0,0,195,229,1,0,0,0,196,197,5,9,0,0,197,198,5,15,0,0,198,207,3,
        42,21,0,199,201,5,15,0,0,200,199,1,0,0,0,200,201,1,0,0,0,201,202,
        1,0,0,0,202,204,5,40,0,0,203,205,5,15,0,0,204,203,1,0,0,0,204,205,
        1,0,0,0,205,206,1,0,0,0,206,208,3,42,21,0,207,200,1,0,0,0,207,208,
        1,0,0,0,208,209,1,0,0,0,209,210,5,15,0,0,210,211,5,10,0,0,211,212,
        5,15,0,0,212,214,3,24,12,0,213,215,5,15,0,0,214,213,1,0,0,0,214,
        215,1,0,0,0,215,216,1,0,0,0,216,217,5,38,0,0,217,218,3,22,11,0,218,
        229,1,0,0,0,219,220,5,11,0,0,220,221,5,15,0,0,221,223,3,28,14,0,
        222,224,5,15,0,0,223,222,1,0,0,0,223,224,1,0,0,0,224,225,1,0,0,0,
        225,226,5,38,0,0,226,227,3,22,11,0,227,229,1,0,0,0,228,185,1,0,0,
        0,228,196,1,0,0,0,228,219,1,0,0,0,229,17,1,0,0,0,230,232,5,8,0,0,
        231,233,5,15,0,0,232,231,1,0,0,0,232,233,1,0,0,0,233,234,1,0,0,0,
        234,235,5,38,0,0,235,236,3,22,11,0,236,19,1,0,0,0,237,238,5,6,0,
        0,238,239,5,15,0,0,239,241,3,42,21,0,240,242,5,15,0,0,241,240,1,
        0,0,0,241,242,1,0,0,0,242,243,1,0,0,0,243,245,5,33,0,0,244,246,3,
        26,13,0,245,244,1,0,0,0,245,246,1,0,0,0,246,247,1,0,0,0,247,249,
        5,34,0,0,248,250,5,15,0,0,249,248,1,0,0,0,249,250,1,0,0,0,250,251,
        1,0,0,0,251,252,5,38,0,0,252,253,3,22,11,0,253,21,1,0,0,0,254,259,
        5,72,0,0,255,257,3,2,1,0,256,258,5,14,0,0,257,256,1,0,0,0,257,258,
        1,0,0,0,258,260,1,0,0,0,259,255,1,0,0,0,260,261,1,0,0,0,261,259,
        1,0,0,0,261,262,1,0,0,0,262,263,1,0,0,0,263,264,5,73,0,0,264,23,
        1,0,0,0,265,288,3,46,23,0,266,267,5,1,0,0,267,269,5,33,0,0,268,270,
        5,15,0,0,269,268,1,0,0,0,269,270,1,0,0,0,270,271,1,0,0,0,271,273,
        3,44,22,0,272,274,5,15,0,0,273,272,1,0,0,0,273,274,1,0,0,0,274,283,
        1,0,0,0,275,277,5,40,0,0,276,278,5,15,0,0,277,276,1,0,0,0,277,278,
        1,0,0,0,278,279,1,0,0,0,279,281,3,44,22,0,280,282,5,15,0,0,281,280,
        1,0,0,0,281,282,1,0,0,0,282,284,1,0,0,0,283,275,1,0,0,0,283,284,
        1,0,0,0,284,285,1,0,0,0,285,286,5,34,0,0,286,288,1,0,0,0,287,265,
        1,0,0,0,287,266,1,0,0,0,288,25,1,0,0,0,289,300,3,42,21,0,290,292,
        5,15,0,0,291,290,1,0,0,0,291,292,1,0,0,0,292,293,1,0,0,0,293,295,
        5,40,0,0,294,296,5,15,0,0,295,294,1,0,0,0,295,296,1,0,0,0,296,297,
        1,0,0,0,297,299,3,42,21,0,298,291,1,0,0,0,299,302,1,0,0,0,300,298,
        1,0,0,0,300,301,1,0,0,0,301,27,1,0,0,0,302,300,1,0,0,0,303,304,3,
        4,2,0,304,29,1,0,0,0,305,306,7,1,0,0,306,31,1,0,0,0,307,309,3,42,
        21,0,308,310,5,15,0,0,309,308,1,0,0,0,309,310,1,0,0,0,310,311,1,
        0,0,0,311,313,5,33,0,0,312,314,5,15,0,0,313,312,1,0,0,0,313,314,
        1,0,0,0,314,318,1,0,0,0,315,317,3,34,17,0,316,315,1,0,0,0,317,320,
        1,0,0,0,318,316,1,0,0,0,318,319,1,0,0,0,319,321,1,0,0,0,320,318,
        1,0,0,0,321,322,5,34,0,0,322,33,1,0,0,0,323,331,3,36,18,0,324,331,
        3,50,25,0,325,331,3,58,29,0,326,327,5,33,0,0,327,328,3,34,17,0,328,
        329,5,34,0,0,329,331,1,0,0,0,330,323,1,0,0,0,330,324,1,0,0,0,330,
        325,1,0,0,0,330,326,1,0,0,0,331,332,1,0,0,0,332,330,1,0,0,0,332,
        333,1,0,0,0,333,35,1,0,0,0,334,335,7,2,0,0,335,336,5,44,0,0,336,
        357,3,42,21,0,337,357,5,25,0,0,338,339,5,24,0,0,339,341,5,46,0,0,
        340,342,5,15,0,0,341,340,1,0,0,0,341,342,1,0,0,0,342,343,1,0,0,0,
        343,352,3,44,22,0,344,346,5,15,0,0,345,344,1,0,0,0,345,346,1,0,0,
        0,346,347,1,0,0,0,347,349,5,32,0,0,348,350,5,15,0,0,349,348,1,0,
        0,0,349,350,1,0,0,0,350,351,1,0,0,0,351,353,5,17,0,0,352,345,1,0,
        0,0,352,353,1,0,0,0,353,354,1,0,0,0,354,355,5,47,0,0,355,357,1,0,
        0,0,356,334,1,0,0,0,356,337,1,0,0,0,356,338,1,0,0,0,357,37,1,0,0,
        0,358,364,3,42,21,0,359,363,3,50,25,0,360,363,3,58,29,0,361,363,
        3,36,18,0,362,359,1,0,0,0,362,360,1,0,0,0,362,361,1,0,0,0,363,366,
        1,0,0,0,364,362,1,0,0,0,364,365,1,0,0,0,365,39,1,0,0,0,366,364,1,
        0,0,0,367,370,3,42,21,0,368,370,3,44,22,0,369,367,1,0,0,0,369,368,
        1,0,0,0,370,41,1,0,0,0,371,377,5,19,0,0,372,377,5,69,0,0,373,374,
        3,48,24,0,374,375,5,69,0,0,375,377,1,0,0,0,376,371,1,0,0,0,376,372,
        1,0,0,0,376,373,1,0,0,0,377,384,1,0,0,0,378,383,5,19,0,0,379,383,
        5,17,0,0,380,383,5,69,0,0,381,383,3,48,24,0,382,378,1,0,0,0,382,
        379,1,0,0,0,382,380,1,0,0,0,382,381,1,0,0,0,383,386,1,0,0,0,384,
        382,1,0,0,0,384,385,1,0,0,0,385,43,1,0,0,0,386,384,1,0,0,0,387,388,
        7,3,0,0,388,45,1,0,0,0,389,390,6,23,-1,0,390,463,3,42,21,0,391,393,
        7,4,0,0,392,391,1,0,0,0,392,393,1,0,0,0,393,394,1,0,0,0,394,463,
        5,17,0,0,395,463,5,16,0,0,396,463,5,12,0,0,397,463,3,36,18,0,398,
        400,5,46,0,0,399,401,5,15,0,0,400,399,1,0,0,0,400,401,1,0,0,0,401,
        402,1,0,0,0,402,413,3,46,23,0,403,405,5,15,0,0,404,403,1,0,0,0,404,
        405,1,0,0,0,405,406,1,0,0,0,406,408,5,40,0,0,407,409,5,15,0,0,408,
        407,1,0,0,0,408,409,1,0,0,0,409,410,1,0,0,0,410,412,3,46,23,0,411,
        404,1,0,0,0,412,415,1,0,0,0,413,411,1,0,0,0,413,414,1,0,0,0,414,
        417,1,0,0,0,415,413,1,0,0,0,416,418,5,15,0,0,417,416,1,0,0,0,417,
        418,1,0,0,0,418,419,1,0,0,0,419,420,5,47,0,0,420,463,1,0,0,0,421,
        423,5,48,0,0,422,424,5,15,0,0,423,422,1,0,0,0,423,424,1,0,0,0,424,
        453,1,0,0,0,425,427,5,26,0,0,426,428,5,15,0,0,427,426,1,0,0,0,427,
        428,1,0,0,0,428,429,1,0,0,0,429,431,5,38,0,0,430,432,5,15,0,0,431,
        430,1,0,0,0,431,432,1,0,0,0,432,433,1,0,0,0,433,435,3,46,23,0,434,
        436,5,15,0,0,435,434,1,0,0,0,435,436,1,0,0,0,436,437,1,0,0,0,437,
        439,5,40,0,0,438,440,5,15,0,0,439,438,1,0,0,0,439,440,1,0,0,0,440,
        441,1,0,0,0,441,443,5,26,0,0,442,444,5,15,0,0,443,442,1,0,0,0,443,
        444,1,0,0,0,444,445,1,0,0,0,445,447,5,38,0,0,446,448,5,15,0,0,447,
        446,1,0,0,0,447,448,1,0,0,0,448,449,1,0,0,0,449,450,3,46,23,0,450,
        452,1,0,0,0,451,425,1,0,0,0,452,455,1,0,0,0,453,451,1,0,0,0,453,
        454,1,0,0,0,454,457,1,0,0,0,455,453,1,0,0,0,456,458,5,15,0,0,457,
        456,1,0,0,0,457,458,1,0,0,0,458,459,1,0,0,0,459,463,5,49,0,0,460,
        463,5,26,0,0,461,463,5,29,0,0,462,389,1,0,0,0,462,392,1,0,0,0,462,
        395,1,0,0,0,462,396,1,0,0,0,462,397,1,0,0,0,462,398,1,0,0,0,462,
        421,1,0,0,0,462,460,1,0,0,0,462,461,1,0,0,0,463,518,1,0,0,0,464,
        465,10,8,0,0,465,466,5,44,0,0,466,517,3,42,21,0,467,468,10,7,0,0,
        468,470,5,46,0,0,469,471,5,15,0,0,470,469,1,0,0,0,470,471,1,0,0,
        0,471,472,1,0,0,0,472,474,3,40,20,0,473,475,5,15,0,0,474,473,1,0,
        0,0,474,475,1,0,0,0,475,476,1,0,0,0,476,477,5,47,0,0,477,517,1,0,
        0,0,478,479,10,6,0,0,479,481,5,46,0,0,480,482,5,15,0,0,481,480,1,
        0,0,0,481,482,1,0,0,0,482,483,1,0,0,0,483,485,3,44,22,0,484,486,
        5,15,0,0,485,484,1,0,0,0,485,486,1,0,0,0,486,487,1,0,0,0,487,489,
        5,38,0,0,488,490,5,15,0,0,489,488,1,0,0,0,489,490,1,0,0,0,490,491,
        1,0,0,0,491,493,3,44,22,0,492,494,5,15,0,0,493,492,1,0,0,0,493,494,
        1,0,0,0,494,495,1,0,0,0,495,496,5,47,0,0,496,517,1,0,0,0,497,498,
        10,5,0,0,498,500,5,46,0,0,499,501,5,15,0,0,500,499,1,0,0,0,500,501,
        1,0,0,0,501,502,1,0,0,0,502,504,3,44,22,0,503,505,5,15,0,0,504,503,
        1,0,0,0,504,505,1,0,0,0,505,506,1,0,0,0,506,508,5,32,0,0,507,509,
        5,15,0,0,508,507,1,0,0,0,508,509,1,0,0,0,509,510,1,0,0,0,510,512,
        5,17,0,0,511,513,5,15,0,0,512,511,1,0,0,0,512,513,1,0,0,0,513,514,
        1,0,0,0,514,515,5,47,0,0,515,517,1,0,0,0,516,464,1,0,0,0,516,467,
        1,0,0,0,516,478,1,0,0,0,516,497,1,0,0,0,517,520,1,0,0,0,518,516,
        1,0,0,0,518,519,1,0,0,0,519,47,1,0,0,0,520,518,1,0,0,0,521,522,7,
        5,0,0,522,49,1,0,0,0,523,527,3,52,26,0,524,527,3,54,27,0,525,527,
        3,56,28,0,526,523,1,0,0,0,526,524,1,0,0,0,526,525,1,0,0,0,527,51,
        1,0,0,0,528,529,5,37,0,0,529,530,5,33,0,0,530,531,3,38,19,0,531,
        532,5,34,0,0,532,53,1,0,0,0,533,534,5,36,0,0,534,535,5,33,0,0,535,
        536,3,4,2,0,536,537,5,34,0,0,537,55,1,0,0,0,538,539,5,35,0,0,539,
        540,5,33,0,0,540,541,3,34,17,0,541,542,5,34,0,0,542,57,1,0,0,0,543,
        552,5,19,0,0,544,552,5,17,0,0,545,552,3,60,30,0,546,552,5,26,0,0,
        547,548,5,33,0,0,548,549,3,58,29,0,549,550,5,34,0,0,550,552,1,0,
        0,0,551,543,1,0,0,0,551,544,1,0,0,0,551,545,1,0,0,0,551,546,1,0,
        0,0,551,547,1,0,0,0,552,59,1,0,0,0,553,554,7,6,0,0,554,61,1,0,0,
        0,92,65,71,73,76,93,100,105,110,114,118,122,126,130,136,140,148,
        152,156,158,162,165,169,183,189,194,200,204,207,214,223,228,232,
        241,245,249,257,261,269,273,277,281,283,287,291,295,300,309,313,
        318,330,332,341,345,349,352,356,362,364,369,376,382,384,392,400,
        404,408,413,417,423,427,431,435,439,443,447,453,457,462,470,474,
        481,485,489,493,500,504,508,512,516,518,526,551
    ]

class dAngrParser ( Parser ):

    grammarFileName = "dAngr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'range'", "'static'", "'IIF'", "'THEN'", 
                     "'ELSE'", "'def'", "'if'", "'else'", "'for'", "'in'", 
                     "'while'", "<INVALID>", "'help'", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "'&sym'", "'&reg'", "'&vars'", "'&mem'", 
                     "'&state'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'->'", "'('", 
                     "')'", "'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", 
                     "'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", "'}'", 
                     "'^'", "'#'", "'%'", "'*'", "'+'", "'/'", "'**'", "'='", 
                     "'=='", "'!='", "'<'", "'>'", "'<='", "'>='", "'&&'", 
                     "'||'", "'?'", "'~'", "'`'", "'_'", "'-'" ]

    symbolicNames = [ "<INVALID>", "<INVALID>", "STATIC", "CIF", "CTHEN", 
                      "CELSE", "DEF", "IF", "ELSE", "FOR", "IN", "WHILE", 
                      "BOOL", "HELP", "NEWLINE", "WS", "HEX_NUMBERS", "NUMBERS", 
                      "NUMBER", "LETTERS", "LETTER", "SYM_DB", "REG_DB", 
                      "VARS_DB", "MEM_DB", "STATE", "STRING", "ESCAPED_QUOTE", 
                      "ESCAPED_SINGLE_QUOTE", "BINARY_STRING", "SESC_SEQ", 
                      "ESC_SEQ", "ARROW", "LPAREN", "RPAREN", "BANG", "AMP", 
                      "DOLLAR", "COLON", "SCOLON", "COMMA", "QUOTE", "SQUOTE", 
                      "AT", "DOT", "BAR", "BRA", "KET", "BRACE", "KETCE", 
                      "HAT", "HASH", "PERC", "TIMES", "ADD", "DIV", "POW", 
                      "ASSIGN", "EQ", "NEQ", "LT", "GT", "LE", "GE", "AND", 
                      "OR", "QMARK", "TILDE", "TICK", "UNDERSCORE", "DASH", 
                      "SUB", "INDENT", "DEDENT" ]

    RULE_script = 0
    RULE_statement = 1
    RULE_expression = 2
    RULE_constraint = 3
    RULE_expression_part = 4
    RULE_assignment = 5
    RULE_static_var = 6
    RULE_ext_command = 7
    RULE_control_flow = 8
    RULE_else_ = 9
    RULE_function_def = 10
    RULE_body = 11
    RULE_iterable = 12
    RULE_parameters = 13
    RULE_condition = 14
    RULE_operation = 15
    RULE_py_basic_content = 16
    RULE_py_content = 17
    RULE_reference = 18
    RULE_bash_content = 19
    RULE_index = 20
    RULE_identifier = 21
    RULE_numeric = 22
    RULE_object = 23
    RULE_special_words = 24
    RULE_range = 25
    RULE_bash_range = 26
    RULE_dangr_range = 27
    RULE_python_range = 28
    RULE_anything = 29
    RULE_symbol = 30

    ruleNames =  [ "script", "statement", "expression", "constraint", "expression_part", 
                   "assignment", "static_var", "ext_command", "control_flow", 
                   "else_", "function_def", "body", "iterable", "parameters", 
                   "condition", "operation", "py_basic_content", "py_content", 
                   "reference", "bash_content", "index", "identifier", "numeric", 
                   "object", "special_words", "range", "bash_range", "dangr_range", 
                   "python_range", "anything", "symbol" ]

    EOF = Token.EOF
    T__0=1
    STATIC=2
    CIF=3
    CTHEN=4
    CELSE=5
    DEF=6
    IF=7
    ELSE=8
    FOR=9
    IN=10
    WHILE=11
    BOOL=12
    HELP=13
    NEWLINE=14
    WS=15
    HEX_NUMBERS=16
    NUMBERS=17
    NUMBER=18
    LETTERS=19
    LETTER=20
    SYM_DB=21
    REG_DB=22
    VARS_DB=23
    MEM_DB=24
    STATE=25
    STRING=26
    ESCAPED_QUOTE=27
    ESCAPED_SINGLE_QUOTE=28
    BINARY_STRING=29
    SESC_SEQ=30
    ESC_SEQ=31
    ARROW=32
    LPAREN=33
    RPAREN=34
    BANG=35
    AMP=36
    DOLLAR=37
    COLON=38
    SCOLON=39
    COMMA=40
    QUOTE=41
    SQUOTE=42
    AT=43
    DOT=44
    BAR=45
    BRA=46
    KET=47
    BRACE=48
    KETCE=49
    HAT=50
    HASH=51
    PERC=52
    TIMES=53
    ADD=54
    DIV=55
    POW=56
    ASSIGN=57
    EQ=58
    NEQ=59
    LT=60
    GT=61
    LE=62
    GE=63
    AND=64
    OR=65
    QMARK=66
    TILDE=67
    TICK=68
    UNDERSCORE=69
    DASH=70
    SUB=71
    INDENT=72
    DEDENT=73

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
            self.state = 76
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,3,self._ctx)
            if la_ == 1:
                self.state = 62
                _la = self._input.LA(1)
                if not(_la==13 or _la==66):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 65
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 63
                    self.match(dAngrParser.WS)
                    self.state = 64
                    self.identifier()


                self.state = 67
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 2:
                self.state = 73
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while (((_la) & ~0x3f) == 0 and ((1 << _la) & 18366492008218620) != 0) or _la==69 or _la==71:
                    self.state = 71
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
                    if la_ == 1:
                        self.state = 68
                        self.match(dAngrParser.NEWLINE)
                        pass

                    elif la_ == 2:
                        self.state = 69
                        self.statement()
                        pass

                    elif la_ == 3:
                        self.state = 70
                        self.function_def()
                        pass


                    self.state = 75
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                pass


            self.state = 78
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


        def assignment(self):
            return self.getTypedRuleContext(dAngrParser.AssignmentContext,0)


        def NEWLINE(self):
            return self.getToken(dAngrParser.NEWLINE, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def static_var(self):
            return self.getTypedRuleContext(dAngrParser.Static_varContext,0)


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
            self.state = 93
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,4,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 80
                self.control_flow()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 81
                self.assignment()
                self.state = 82
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 84
                self.expression()
                self.state = 85
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 87
                self.static_var()
                self.state = 88
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 90
                self.ext_command()
                self.state = 91
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

        def expression_part(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Expression_partContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Expression_partContext,i)


        def ASSIGN(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.ASSIGN)
            else:
                return self.getToken(dAngrParser.ASSIGN, i)

        def constraint(self):
            return self.getTypedRuleContext(dAngrParser.ConstraintContext,0)


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
            self.state = 110
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,7,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 95
                self.identifier()
                self.state = 105
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,6,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 96
                        self.match(dAngrParser.WS)
                        self.state = 100
                        self._errHandler.sync(self)
                        la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
                        if la_ == 1:
                            self.state = 97
                            self.identifier()
                            self.state = 98
                            self.match(dAngrParser.ASSIGN)


                        self.state = 102
                        self.expression_part() 
                    self.state = 107
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,6,self._ctx)

                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 108
                self.constraint()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 109
                self.expression_part()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ConstraintContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def CIF(self):
            return self.getToken(dAngrParser.CIF, 0)

        def condition(self):
            return self.getTypedRuleContext(dAngrParser.ConditionContext,0)


        def CTHEN(self):
            return self.getToken(dAngrParser.CTHEN, 0)

        def expression_part(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Expression_partContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Expression_partContext,i)


        def CELSE(self):
            return self.getToken(dAngrParser.CELSE, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def getRuleIndex(self):
            return dAngrParser.RULE_constraint

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterConstraint" ):
                listener.enterConstraint(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitConstraint" ):
                listener.exitConstraint(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitConstraint" ):
                return visitor.visitConstraint(self)
            else:
                return visitor.visitChildren(self)




    def constraint(self):

        localctx = dAngrParser.ConstraintContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_constraint)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 112
            self.match(dAngrParser.CIF)
            self.state = 114
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 113
                self.match(dAngrParser.WS)


            self.state = 116
            self.condition()
            self.state = 118
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 117
                self.match(dAngrParser.WS)


            self.state = 120
            self.match(dAngrParser.CTHEN)
            self.state = 122
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 121
                self.match(dAngrParser.WS)


            self.state = 124
            self.expression_part()
            self.state = 126
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 125
                self.match(dAngrParser.WS)


            self.state = 128
            self.match(dAngrParser.CELSE)
            self.state = 130
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 129
                self.match(dAngrParser.WS)


            self.state = 132
            self.expression_part()
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

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def range_(self):
            return self.getTypedRuleContext(dAngrParser.RangeContext,0)


        def reference(self):
            return self.getTypedRuleContext(dAngrParser.ReferenceContext,0)


        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def operation(self):
            return self.getTypedRuleContext(dAngrParser.OperationContext,0)


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
        self.enterRule(localctx, 8, self.RULE_expression_part)
        self._la = 0 # Token type
        try:
            self.state = 158
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,18,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 134
                self.match(dAngrParser.LPAREN)
                self.state = 136
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 135
                    self.match(dAngrParser.WS)


                self.state = 138
                self.expression()
                self.state = 140
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 139
                    self.match(dAngrParser.WS)


                self.state = 142
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 144
                self.range_()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 145
                self.reference()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 146
                self.object_(0)
                self.state = 156
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,17,self._ctx)
                if la_ == 1:
                    self.state = 148
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 147
                        self.match(dAngrParser.WS)


                    self.state = 150
                    self.operation()
                    self.state = 152
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 151
                        self.match(dAngrParser.WS)


                    self.state = 154
                    self.expression()


                pass


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

        def ASSIGN(self):
            return self.getToken(dAngrParser.ASSIGN, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def static_var(self):
            return self.getTypedRuleContext(dAngrParser.Static_varContext,0)


        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


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
        self.enterRule(localctx, 10, self.RULE_assignment)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 162
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                self.state = 160
                self.static_var()
                pass

            elif la_ == 2:
                self.state = 161
                self.object_(0)
                pass


            self.state = 165
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 164
                self.match(dAngrParser.WS)


            self.state = 167
            self.match(dAngrParser.ASSIGN)
            self.state = 169
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 168
                self.match(dAngrParser.WS)


            self.state = 171
            self.expression()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class Static_varContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def STATIC(self):
            return self.getToken(dAngrParser.STATIC, 0)

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_static_var

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStatic_var" ):
                listener.enterStatic_var(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStatic_var" ):
                listener.exitStatic_var(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStatic_var" ):
                return visitor.visitStatic_var(self)
            else:
                return visitor.visitChildren(self)




    def static_var(self):

        localctx = dAngrParser.Static_varContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_static_var)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 173
            self.match(dAngrParser.STATIC)
            self.state = 174
            self.match(dAngrParser.WS)
            self.state = 175
            self.identifier()
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

        def py_basic_content(self):
            return self.getTypedRuleContext(dAngrParser.Py_basic_contentContext,0)


        def AMP(self):
            return self.getToken(dAngrParser.AMP, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


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
            self.state = 183
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [35]:
                self.enterOuterAlt(localctx, 1)
                self.state = 177
                self.match(dAngrParser.BANG)
                self.state = 178
                self.py_basic_content()
                pass
            elif token in [36]:
                self.enterOuterAlt(localctx, 2)
                self.state = 179
                self.match(dAngrParser.AMP)
                self.state = 180
                self.expression()
                pass
            elif token in [37]:
                self.enterOuterAlt(localctx, 3)
                self.state = 181
                self.match(dAngrParser.DOLLAR)
                self.state = 182
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
            self.state = 228
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [7]:
                self.enterOuterAlt(localctx, 1)
                self.state = 185
                self.match(dAngrParser.IF)
                self.state = 186
                self.match(dAngrParser.WS)
                self.state = 187
                self.condition()
                self.state = 189
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 188
                    self.match(dAngrParser.WS)


                self.state = 191
                self.match(dAngrParser.COLON)
                self.state = 192
                self.body()
                self.state = 194
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,24,self._ctx)
                if la_ == 1:
                    self.state = 193
                    self.else_()


                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 2)
                self.state = 196
                self.match(dAngrParser.FOR)
                self.state = 197
                self.match(dAngrParser.WS)
                self.state = 198
                self.identifier()
                self.state = 207
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,27,self._ctx)
                if la_ == 1:
                    self.state = 200
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 199
                        self.match(dAngrParser.WS)


                    self.state = 202
                    self.match(dAngrParser.COMMA)
                    self.state = 204
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 203
                        self.match(dAngrParser.WS)


                    self.state = 206
                    self.identifier()


                self.state = 209
                self.match(dAngrParser.WS)
                self.state = 210
                self.match(dAngrParser.IN)
                self.state = 211
                self.match(dAngrParser.WS)
                self.state = 212
                self.iterable()
                self.state = 214
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 213
                    self.match(dAngrParser.WS)


                self.state = 216
                self.match(dAngrParser.COLON)
                self.state = 217
                self.body()
                pass
            elif token in [11]:
                self.enterOuterAlt(localctx, 3)
                self.state = 219
                self.match(dAngrParser.WHILE)
                self.state = 220
                self.match(dAngrParser.WS)
                self.state = 221
                self.condition()
                self.state = 223
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 222
                    self.match(dAngrParser.WS)


                self.state = 225
                self.match(dAngrParser.COLON)
                self.state = 226
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
            self.state = 230
            self.match(dAngrParser.ELSE)
            self.state = 232
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 231
                self.match(dAngrParser.WS)


            self.state = 234
            self.match(dAngrParser.COLON)
            self.state = 235
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
            self.state = 237
            self.match(dAngrParser.DEF)
            self.state = 238
            self.match(dAngrParser.WS)
            self.state = 239
            self.identifier()
            self.state = 241
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 240
                self.match(dAngrParser.WS)


            self.state = 243
            self.match(dAngrParser.LPAREN)
            self.state = 245
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if (((_la) & ~0x3f) == 0 and ((1 << _la) & 540668) != 0) or _la==69:
                self.state = 244
                self.parameters()


            self.state = 247
            self.match(dAngrParser.RPAREN)
            self.state = 249
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 248
                self.match(dAngrParser.WS)


            self.state = 251
            self.match(dAngrParser.COLON)
            self.state = 252
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
            self.state = 254
            self.match(dAngrParser.INDENT)
            self.state = 259 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 255
                self.statement()
                self.state = 257
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==14:
                    self.state = 256
                    self.match(dAngrParser.NEWLINE)


                self.state = 261 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 18366492008202236) != 0) or _la==69 or _la==71):
                    break

            self.state = 263
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
            self.state = 287
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 19, 21, 22, 23, 24, 25, 26, 29, 46, 48, 54, 69, 71]:
                self.enterOuterAlt(localctx, 1)
                self.state = 265
                self.object_(0)
                pass
            elif token in [1]:
                self.enterOuterAlt(localctx, 2)
                self.state = 266
                self.match(dAngrParser.T__0)
                self.state = 267
                self.match(dAngrParser.LPAREN)
                self.state = 269
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 268
                    self.match(dAngrParser.WS)


                self.state = 271
                self.numeric()
                self.state = 273
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 272
                    self.match(dAngrParser.WS)


                self.state = 283
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==40:
                    self.state = 275
                    self.match(dAngrParser.COMMA)
                    self.state = 277
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 276
                        self.match(dAngrParser.WS)


                    self.state = 279
                    self.numeric()
                    self.state = 281
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 280
                        self.match(dAngrParser.WS)




                self.state = 285
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
            self.state = 289
            self.identifier()
            self.state = 300
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==15 or _la==40:
                self.state = 291
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 290
                    self.match(dAngrParser.WS)


                self.state = 293
                self.match(dAngrParser.COMMA)
                self.state = 295
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 294
                    self.match(dAngrParser.WS)


                self.state = 297
                self.identifier()
                self.state = 302
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
            self.state = 303
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

        def DASH(self):
            return self.getToken(dAngrParser.DASH, 0)

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
            self.state = 305
            _la = self._input.LA(1)
            if not(((((_la - 52)) & ~0x3f) == 0 and ((1 << (_la - 52)) & 278495) != 0)):
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


    class Py_basic_contentContext(ParserRuleContext):
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

        def py_content(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Py_contentContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Py_contentContext,i)


        def getRuleIndex(self):
            return dAngrParser.RULE_py_basic_content

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPy_basic_content" ):
                listener.enterPy_basic_content(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPy_basic_content" ):
                listener.exitPy_basic_content(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPy_basic_content" ):
                return visitor.visitPy_basic_content(self)
            else:
                return visitor.visitChildren(self)




    def py_basic_content(self):

        localctx = dAngrParser.Py_basic_contentContext(self, self._ctx, self.state)
        self.enterRule(localctx, 32, self.RULE_py_basic_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 307
            self.identifier()
            self.state = 309
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==15:
                self.state = 308
                self.match(dAngrParser.WS)


            self.state = 311
            self.match(dAngrParser.LPAREN)
            self.state = 313
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,47,self._ctx)
            if la_ == 1:
                self.state = 312
                self.match(dAngrParser.WS)


            self.state = 318
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 15)) & ~0x3f) == 0 and ((1 << (_la - 15)) & 72057594037145557) != 0):
                self.state = 315
                self.py_content()
                self.state = 320
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 321
            self.match(dAngrParser.RPAREN)
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

        def reference(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ReferenceContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ReferenceContext,i)


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


        def LPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.LPAREN)
            else:
                return self.getToken(dAngrParser.LPAREN, i)

        def py_content(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Py_contentContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Py_contentContext,i)


        def RPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.RPAREN)
            else:
                return self.getToken(dAngrParser.RPAREN, i)

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
        self.enterRule(localctx, 34, self.RULE_py_content)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 330 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 330
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,49,self._ctx)
                    if la_ == 1:
                        self.state = 323
                        self.reference()
                        pass

                    elif la_ == 2:
                        self.state = 324
                        self.range_()
                        pass

                    elif la_ == 3:
                        self.state = 325
                        self.anything()
                        pass

                    elif la_ == 4:
                        self.state = 326
                        self.match(dAngrParser.LPAREN)
                        self.state = 327
                        self.py_content()
                        self.state = 328
                        self.match(dAngrParser.RPAREN)
                        pass



                else:
                    raise NoViableAltException(self)
                self.state = 332 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,50,self._ctx)

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

        def STATE(self):
            return self.getToken(dAngrParser.STATE, 0)

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
        self.enterRule(localctx, 36, self.RULE_reference)
        self._la = 0 # Token type
        try:
            self.state = 356
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [21, 22, 23]:
                self.enterOuterAlt(localctx, 1)
                self.state = 334
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 14680064) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 335
                self.match(dAngrParser.DOT)
                self.state = 336
                self.identifier()
                pass
            elif token in [25]:
                self.enterOuterAlt(localctx, 2)
                self.state = 337
                self.match(dAngrParser.STATE)
                pass
            elif token in [24]:
                self.enterOuterAlt(localctx, 3)
                self.state = 338
                self.match(dAngrParser.MEM_DB)
                self.state = 339
                self.match(dAngrParser.BRA)
                self.state = 341
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 340
                    self.match(dAngrParser.WS)


                self.state = 343
                self.numeric()
                self.state = 352
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15 or _la==32:
                    self.state = 345
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 344
                        self.match(dAngrParser.WS)


                    self.state = 347
                    self.match(dAngrParser.ARROW)
                    self.state = 349
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 348
                        self.match(dAngrParser.WS)


                    self.state = 351
                    self.match(dAngrParser.NUMBERS)


                self.state = 354
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
        self.enterRule(localctx, 38, self.RULE_bash_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 358
            self.identifier()
            self.state = 364
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 15)) & ~0x3f) == 0 and ((1 << (_la - 15)) & 72057594037145557) != 0):
                self.state = 362
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,56,self._ctx)
                if la_ == 1:
                    self.state = 359
                    self.range_()
                    pass

                elif la_ == 2:
                    self.state = 360
                    self.anything()
                    pass

                elif la_ == 3:
                    self.state = 361
                    self.reference()
                    pass


                self.state = 366
                self._errHandler.sync(self)
                _la = self._input.LA(1)

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
        self.enterRule(localctx, 40, self.RULE_index)
        try:
            self.state = 369
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 19, 69]:
                self.enterOuterAlt(localctx, 1)
                self.state = 367
                self.identifier()
                pass
            elif token in [16, 17]:
                self.enterOuterAlt(localctx, 2)
                self.state = 368
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

        def special_words(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Special_wordsContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Special_wordsContext,i)


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
        self.enterRule(localctx, 42, self.RULE_identifier)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 376
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [19]:
                self.state = 371
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [69]:
                self.state = 372
                self.match(dAngrParser.UNDERSCORE)
                pass
            elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
                self.state = 373
                self.special_words()
                self.state = 374
                self.match(dAngrParser.UNDERSCORE)
                pass
            else:
                raise NoViableAltException(self)

            self.state = 384
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,61,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 382
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [19]:
                        self.state = 378
                        self.match(dAngrParser.LETTERS)
                        pass
                    elif token in [17]:
                        self.state = 379
                        self.match(dAngrParser.NUMBERS)
                        pass
                    elif token in [69]:
                        self.state = 380
                        self.match(dAngrParser.UNDERSCORE)
                        pass
                    elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
                        self.state = 381
                        self.special_words()
                        pass
                    else:
                        raise NoViableAltException(self)
             
                self.state = 386
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,61,self._ctx)

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
        self.enterRule(localctx, 44, self.RULE_numeric)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 387
            _la = self._input.LA(1)
            if not(_la==16 or _la==17):
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

        def ADD(self):
            return self.getToken(dAngrParser.ADD, 0)

        def SUB(self):
            return self.getToken(dAngrParser.SUB, 0)

        def HEX_NUMBERS(self):
            return self.getToken(dAngrParser.HEX_NUMBERS, 0)

        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

        def reference(self):
            return self.getTypedRuleContext(dAngrParser.ReferenceContext,0)


        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)

        def object_(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.ObjectContext)
            else:
                return self.getTypedRuleContext(dAngrParser.ObjectContext,i)


        def KET(self):
            return self.getToken(dAngrParser.KET, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

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

        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

        def index(self):
            return self.getTypedRuleContext(dAngrParser.IndexContext,0)


        def numeric(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.NumericContext)
            else:
                return self.getTypedRuleContext(dAngrParser.NumericContext,i)


        def ARROW(self):
            return self.getToken(dAngrParser.ARROW, 0)

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
        _startState = 46
        self.enterRecursionRule(localctx, 46, self.RULE_object, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 462
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,77,self._ctx)
            if la_ == 1:
                self.state = 390
                self.identifier()
                pass

            elif la_ == 2:
                self.state = 392
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==54 or _la==71:
                    self.state = 391
                    _la = self._input.LA(1)
                    if not(_la==54 or _la==71):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()


                self.state = 394
                self.match(dAngrParser.NUMBERS)
                pass

            elif la_ == 3:
                self.state = 395
                self.match(dAngrParser.HEX_NUMBERS)
                pass

            elif la_ == 4:
                self.state = 396
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 5:
                self.state = 397
                self.reference()
                pass

            elif la_ == 6:
                self.state = 398
                self.match(dAngrParser.BRA)
                self.state = 400
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 399
                    self.match(dAngrParser.WS)


                self.state = 402
                self.object_(0)
                self.state = 413
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,66,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 404
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 403
                            self.match(dAngrParser.WS)


                        self.state = 406
                        self.match(dAngrParser.COMMA)
                        self.state = 408
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 407
                            self.match(dAngrParser.WS)


                        self.state = 410
                        self.object_(0) 
                    self.state = 415
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,66,self._ctx)

                self.state = 417
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 416
                    self.match(dAngrParser.WS)


                self.state = 419
                self.match(dAngrParser.KET)
                pass

            elif la_ == 7:
                self.state = 421
                self.match(dAngrParser.BRACE)
                self.state = 423
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,68,self._ctx)
                if la_ == 1:
                    self.state = 422
                    self.match(dAngrParser.WS)


                self.state = 453
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==26:
                    self.state = 425
                    self.match(dAngrParser.STRING)
                    self.state = 427
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 426
                        self.match(dAngrParser.WS)


                    self.state = 429
                    self.match(dAngrParser.COLON)
                    self.state = 431
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 430
                        self.match(dAngrParser.WS)


                    self.state = 433
                    self.object_(0)

                    self.state = 435
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 434
                        self.match(dAngrParser.WS)


                    self.state = 437
                    self.match(dAngrParser.COMMA)
                    self.state = 439
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 438
                        self.match(dAngrParser.WS)


                    self.state = 441
                    self.match(dAngrParser.STRING)
                    self.state = 443
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 442
                        self.match(dAngrParser.WS)


                    self.state = 445
                    self.match(dAngrParser.COLON)
                    self.state = 447
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==15:
                        self.state = 446
                        self.match(dAngrParser.WS)


                    self.state = 449
                    self.object_(0)
                    self.state = 455
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 457
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 456
                    self.match(dAngrParser.WS)


                self.state = 459
                self.match(dAngrParser.KETCE)
                pass

            elif la_ == 8:
                self.state = 460
                self.match(dAngrParser.STRING)
                pass

            elif la_ == 9:
                self.state = 461
                self.match(dAngrParser.BINARY_STRING)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 518
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,89,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 516
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,88,self._ctx)
                    if la_ == 1:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 464
                        if not self.precpred(self._ctx, 8):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 8)")
                        self.state = 465
                        self.match(dAngrParser.DOT)
                        self.state = 466
                        self.identifier()
                        pass

                    elif la_ == 2:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 467
                        if not self.precpred(self._ctx, 7):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 7)")
                        self.state = 468
                        self.match(dAngrParser.BRA)
                        self.state = 470
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 469
                            self.match(dAngrParser.WS)


                        self.state = 472
                        self.index()
                        self.state = 474
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 473
                            self.match(dAngrParser.WS)


                        self.state = 476
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 3:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 478
                        if not self.precpred(self._ctx, 6):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                        self.state = 479
                        self.match(dAngrParser.BRA)
                        self.state = 481
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 480
                            self.match(dAngrParser.WS)


                        self.state = 483
                        self.numeric()
                        self.state = 485
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 484
                            self.match(dAngrParser.WS)


                        self.state = 487
                        self.match(dAngrParser.COLON)
                        self.state = 489
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 488
                            self.match(dAngrParser.WS)


                        self.state = 491
                        self.numeric()
                        self.state = 493
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 492
                            self.match(dAngrParser.WS)


                        self.state = 495
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 4:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 497
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 498
                        self.match(dAngrParser.BRA)
                        self.state = 500
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 499
                            self.match(dAngrParser.WS)


                        self.state = 502
                        self.numeric()
                        self.state = 504
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 503
                            self.match(dAngrParser.WS)


                        self.state = 506
                        self.match(dAngrParser.ARROW)
                        self.state = 508
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 507
                            self.match(dAngrParser.WS)


                        self.state = 510
                        self.match(dAngrParser.NUMBERS)
                        self.state = 512
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==15:
                            self.state = 511
                            self.match(dAngrParser.WS)


                        self.state = 514
                        self.match(dAngrParser.KET)
                        pass

             
                self.state = 520
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,89,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
        return localctx


    class Special_wordsContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def STATIC(self):
            return self.getToken(dAngrParser.STATIC, 0)

        def DEF(self):
            return self.getToken(dAngrParser.DEF, 0)

        def IF(self):
            return self.getToken(dAngrParser.IF, 0)

        def ELSE(self):
            return self.getToken(dAngrParser.ELSE, 0)

        def FOR(self):
            return self.getToken(dAngrParser.FOR, 0)

        def IN(self):
            return self.getToken(dAngrParser.IN, 0)

        def WHILE(self):
            return self.getToken(dAngrParser.WHILE, 0)

        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

        def HELP(self):
            return self.getToken(dAngrParser.HELP, 0)

        def CIF(self):
            return self.getToken(dAngrParser.CIF, 0)

        def CTHEN(self):
            return self.getToken(dAngrParser.CTHEN, 0)

        def CELSE(self):
            return self.getToken(dAngrParser.CELSE, 0)

        def getRuleIndex(self):
            return dAngrParser.RULE_special_words

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSpecial_words" ):
                listener.enterSpecial_words(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSpecial_words" ):
                listener.exitSpecial_words(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSpecial_words" ):
                return visitor.visitSpecial_words(self)
            else:
                return visitor.visitChildren(self)




    def special_words(self):

        localctx = dAngrParser.Special_wordsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 48, self.RULE_special_words)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 521
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 16380) != 0)):
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
        self.enterRule(localctx, 50, self.RULE_range)
        try:
            self.state = 526
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [37]:
                self.enterOuterAlt(localctx, 1)
                self.state = 523
                self.bash_range()
                pass
            elif token in [36]:
                self.enterOuterAlt(localctx, 2)
                self.state = 524
                self.dangr_range()
                pass
            elif token in [35]:
                self.enterOuterAlt(localctx, 3)
                self.state = 525
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
        self.enterRule(localctx, 52, self.RULE_bash_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 528
            self.match(dAngrParser.DOLLAR)
            self.state = 529
            self.match(dAngrParser.LPAREN)
            self.state = 530
            self.bash_content()
            self.state = 531
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

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


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
        self.enterRule(localctx, 54, self.RULE_dangr_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 533
            self.match(dAngrParser.AMP)
            self.state = 534
            self.match(dAngrParser.LPAREN)
            self.state = 535
            self.expression()
            self.state = 536
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
        self.enterRule(localctx, 56, self.RULE_python_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 538
            self.match(dAngrParser.BANG)
            self.state = 539
            self.match(dAngrParser.LPAREN)
            self.state = 540
            self.py_content()
            self.state = 541
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

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def anything(self):
            return self.getTypedRuleContext(dAngrParser.AnythingContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

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
        self.enterRule(localctx, 58, self.RULE_anything)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 551
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [19]:
                self.state = 543
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [17]:
                self.state = 544
                self.match(dAngrParser.NUMBERS)
                pass
            elif token in [15, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70]:
                self.state = 545
                self.symbol()
                pass
            elif token in [26]:
                self.state = 546
                self.match(dAngrParser.STRING)
                pass
            elif token in [33]:
                self.state = 547
                self.match(dAngrParser.LPAREN)
                self.state = 548
                self.anything()
                self.state = 549
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


    class SymbolContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

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
        self.enterRule(localctx, 60, self.RULE_symbol)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 553
            _la = self._input.LA(1)
            if not(((((_la - 15)) & ~0x3f) == 0 and ((1 << (_la - 15)) & 72057594036879361) != 0)):
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
        self._predicates[23] = self.object_sempred
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
         




