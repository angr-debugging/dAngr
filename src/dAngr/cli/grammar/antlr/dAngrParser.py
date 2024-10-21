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
        4,1,76,600,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,1,0,1,0,1,0,3,
        0,68,8,0,1,0,1,0,1,0,1,0,5,0,74,8,0,10,0,12,0,77,9,0,3,0,79,8,0,
        1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,
        96,8,1,1,2,3,2,99,8,2,1,2,1,2,1,2,1,2,1,2,3,2,106,8,2,1,2,5,2,109,
        8,2,10,2,12,2,112,9,2,1,2,1,2,3,2,116,8,2,1,3,1,3,3,3,120,8,3,1,
        3,1,3,3,3,124,8,3,1,3,1,3,3,3,128,8,3,1,3,1,3,3,3,132,8,3,1,3,1,
        3,3,3,136,8,3,1,3,1,3,1,4,1,4,3,4,142,8,4,1,4,1,4,3,4,146,8,4,1,
        4,1,4,1,4,1,4,1,4,1,4,1,4,3,4,155,8,4,1,4,1,4,3,4,159,8,4,1,4,1,
        4,3,4,163,8,4,1,4,3,4,166,8,4,1,5,1,5,3,5,170,8,5,1,5,3,5,173,8,
        5,1,5,1,5,3,5,177,8,5,1,5,1,5,1,6,1,6,1,6,1,6,1,7,1,7,1,7,1,7,1,
        7,1,7,3,7,191,8,7,1,8,1,8,1,8,1,8,3,8,197,8,8,1,8,1,8,1,8,3,8,202,
        8,8,1,8,1,8,1,8,1,8,3,8,208,8,8,1,8,1,8,3,8,212,8,8,1,8,3,8,215,
        8,8,1,8,1,8,1,8,1,8,1,8,3,8,222,8,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,
        3,8,231,8,8,1,8,1,8,1,8,3,8,236,8,8,1,9,1,9,3,9,240,8,9,1,9,1,9,
        1,9,1,10,1,10,1,10,1,10,3,10,249,8,10,1,10,1,10,3,10,253,8,10,1,
        10,1,10,3,10,257,8,10,1,10,1,10,1,10,1,11,1,11,1,11,3,11,265,8,11,
        4,11,267,8,11,11,11,12,11,268,1,11,1,11,1,12,1,12,1,12,1,12,3,12,
        277,8,12,1,13,1,13,1,13,1,13,3,13,283,8,13,1,13,1,13,3,13,287,8,
        13,1,13,1,13,3,13,291,8,13,1,13,1,13,3,13,295,8,13,3,13,297,8,13,
        1,13,1,13,3,13,301,8,13,1,14,1,14,3,14,305,8,14,1,14,1,14,3,14,309,
        8,14,1,14,5,14,312,8,14,10,14,12,14,315,9,14,1,15,1,15,1,16,1,16,
        1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,
        1,16,1,16,1,16,1,16,3,16,338,8,16,1,17,1,17,3,17,342,8,17,1,17,1,
        17,3,17,346,8,17,1,17,5,17,349,8,17,10,17,12,17,352,9,17,1,17,1,
        17,1,18,1,18,1,18,1,18,1,18,1,18,1,18,4,18,363,8,18,11,18,12,18,
        364,1,19,1,19,1,19,1,19,1,19,1,19,1,19,3,19,374,8,19,1,19,1,19,3,
        19,378,8,19,1,19,1,19,3,19,382,8,19,1,19,3,19,385,8,19,1,19,1,19,
        3,19,389,8,19,1,20,1,20,1,20,1,20,5,20,395,8,20,10,20,12,20,398,
        9,20,1,21,1,21,3,21,402,8,21,1,22,1,22,1,22,1,22,1,22,3,22,409,8,
        22,1,22,1,22,1,22,1,22,5,22,415,8,22,10,22,12,22,418,9,22,1,23,1,
        23,1,24,1,24,1,24,3,24,425,8,24,1,24,1,24,1,24,1,24,1,24,1,24,3,
        24,433,8,24,1,24,1,24,3,24,437,8,24,1,24,1,24,3,24,441,8,24,1,24,
        5,24,444,8,24,10,24,12,24,447,9,24,1,24,3,24,450,8,24,1,24,1,24,
        1,24,1,24,3,24,456,8,24,1,24,1,24,3,24,460,8,24,1,24,1,24,3,24,464,
        8,24,1,24,1,24,3,24,468,8,24,1,24,1,24,3,24,472,8,24,1,24,1,24,3,
        24,476,8,24,1,24,1,24,3,24,480,8,24,1,24,1,24,5,24,484,8,24,10,24,
        12,24,487,9,24,1,24,3,24,490,8,24,1,24,1,24,1,24,3,24,495,8,24,1,
        24,1,24,1,24,1,24,1,24,1,24,3,24,503,8,24,1,24,1,24,3,24,507,8,24,
        1,24,1,24,1,24,1,24,1,24,3,24,514,8,24,1,24,3,24,517,8,24,1,24,1,
        24,3,24,521,8,24,1,24,1,24,3,24,525,8,24,1,24,3,24,528,8,24,1,24,
        1,24,3,24,532,8,24,1,24,1,24,1,24,1,24,1,24,3,24,539,8,24,1,24,3,
        24,542,8,24,1,24,1,24,3,24,546,8,24,1,24,1,24,3,24,550,8,24,1,24,
        3,24,553,8,24,1,24,1,24,3,24,557,8,24,1,24,1,24,5,24,561,8,24,10,
        24,12,24,564,9,24,1,25,1,25,1,26,1,26,1,26,3,26,571,8,26,1,27,1,
        27,1,27,1,27,1,27,1,28,1,28,1,28,1,28,1,28,1,29,1,29,1,29,1,29,1,
        29,1,30,1,30,1,30,1,30,1,30,1,30,1,30,1,30,3,30,596,8,30,1,31,1,
        31,1,31,0,1,48,32,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,
        34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,0,6,2,0,13,13,70,70,
        1,0,22,24,1,0,17,18,2,0,55,55,74,74,1,0,2,14,2,0,16,16,36,74,713,
        0,78,1,0,0,0,2,95,1,0,0,0,4,115,1,0,0,0,6,117,1,0,0,0,8,165,1,0,
        0,0,10,169,1,0,0,0,12,180,1,0,0,0,14,190,1,0,0,0,16,235,1,0,0,0,
        18,237,1,0,0,0,20,244,1,0,0,0,22,261,1,0,0,0,24,276,1,0,0,0,26,300,
        1,0,0,0,28,302,1,0,0,0,30,316,1,0,0,0,32,337,1,0,0,0,34,339,1,0,
        0,0,36,362,1,0,0,0,38,388,1,0,0,0,40,390,1,0,0,0,42,401,1,0,0,0,
        44,408,1,0,0,0,46,419,1,0,0,0,48,494,1,0,0,0,50,565,1,0,0,0,52,570,
        1,0,0,0,54,572,1,0,0,0,56,577,1,0,0,0,58,582,1,0,0,0,60,595,1,0,
        0,0,62,597,1,0,0,0,64,67,7,0,0,0,65,66,5,16,0,0,66,68,3,44,22,0,
        67,65,1,0,0,0,67,68,1,0,0,0,68,69,1,0,0,0,69,79,5,15,0,0,70,74,5,
        15,0,0,71,74,3,2,1,0,72,74,3,20,10,0,73,70,1,0,0,0,73,71,1,0,0,0,
        73,72,1,0,0,0,74,77,1,0,0,0,75,73,1,0,0,0,75,76,1,0,0,0,76,79,1,
        0,0,0,77,75,1,0,0,0,78,64,1,0,0,0,78,75,1,0,0,0,79,80,1,0,0,0,80,
        81,5,0,0,1,81,1,1,0,0,0,82,96,3,16,8,0,83,84,3,10,5,0,84,85,5,15,
        0,0,85,96,1,0,0,0,86,87,3,4,2,0,87,88,5,15,0,0,88,96,1,0,0,0,89,
        90,3,12,6,0,90,91,5,15,0,0,91,96,1,0,0,0,92,93,3,14,7,0,93,94,5,
        15,0,0,94,96,1,0,0,0,95,82,1,0,0,0,95,83,1,0,0,0,95,86,1,0,0,0,95,
        89,1,0,0,0,95,92,1,0,0,0,96,3,1,0,0,0,97,99,5,56,0,0,98,97,1,0,0,
        0,98,99,1,0,0,0,99,100,1,0,0,0,100,110,3,44,22,0,101,105,5,16,0,
        0,102,103,3,44,22,0,103,104,5,61,0,0,104,106,1,0,0,0,105,102,1,0,
        0,0,105,106,1,0,0,0,106,107,1,0,0,0,107,109,3,8,4,0,108,101,1,0,
        0,0,109,112,1,0,0,0,110,108,1,0,0,0,110,111,1,0,0,0,111,116,1,0,
        0,0,112,110,1,0,0,0,113,116,3,6,3,0,114,116,3,8,4,0,115,98,1,0,0,
        0,115,113,1,0,0,0,115,114,1,0,0,0,116,5,1,0,0,0,117,119,5,3,0,0,
        118,120,5,16,0,0,119,118,1,0,0,0,119,120,1,0,0,0,120,121,1,0,0,0,
        121,123,3,30,15,0,122,124,5,16,0,0,123,122,1,0,0,0,123,124,1,0,0,
        0,124,125,1,0,0,0,125,127,5,4,0,0,126,128,5,16,0,0,127,126,1,0,0,
        0,127,128,1,0,0,0,128,129,1,0,0,0,129,131,3,8,4,0,130,132,5,16,0,
        0,131,130,1,0,0,0,131,132,1,0,0,0,132,133,1,0,0,0,133,135,5,5,0,
        0,134,136,5,16,0,0,135,134,1,0,0,0,135,136,1,0,0,0,136,137,1,0,0,
        0,137,138,3,8,4,0,138,7,1,0,0,0,139,141,5,34,0,0,140,142,5,16,0,
        0,141,140,1,0,0,0,141,142,1,0,0,0,142,143,1,0,0,0,143,145,3,4,2,
        0,144,146,5,16,0,0,145,144,1,0,0,0,145,146,1,0,0,0,146,147,1,0,0,
        0,147,148,5,35,0,0,148,166,1,0,0,0,149,166,3,52,26,0,150,166,3,38,
        19,0,151,166,5,12,0,0,152,162,3,48,24,0,153,155,5,16,0,0,154,153,
        1,0,0,0,154,155,1,0,0,0,155,156,1,0,0,0,156,158,3,32,16,0,157,159,
        5,16,0,0,158,157,1,0,0,0,158,159,1,0,0,0,159,160,1,0,0,0,160,161,
        3,4,2,0,161,163,1,0,0,0,162,154,1,0,0,0,162,163,1,0,0,0,163,166,
        1,0,0,0,164,166,3,48,24,0,165,139,1,0,0,0,165,149,1,0,0,0,165,150,
        1,0,0,0,165,151,1,0,0,0,165,152,1,0,0,0,165,164,1,0,0,0,166,9,1,
        0,0,0,167,170,3,12,6,0,168,170,3,48,24,0,169,167,1,0,0,0,169,168,
        1,0,0,0,170,172,1,0,0,0,171,173,5,16,0,0,172,171,1,0,0,0,172,173,
        1,0,0,0,173,174,1,0,0,0,174,176,5,61,0,0,175,177,5,16,0,0,176,175,
        1,0,0,0,176,177,1,0,0,0,177,178,1,0,0,0,178,179,3,4,2,0,179,11,1,
        0,0,0,180,181,5,2,0,0,181,182,5,16,0,0,182,183,3,44,22,0,183,13,
        1,0,0,0,184,185,5,36,0,0,185,191,3,34,17,0,186,187,5,37,0,0,187,
        191,3,4,2,0,188,189,5,38,0,0,189,191,3,40,20,0,190,184,1,0,0,0,190,
        186,1,0,0,0,190,188,1,0,0,0,191,15,1,0,0,0,192,193,5,7,0,0,193,194,
        5,16,0,0,194,196,3,30,15,0,195,197,5,16,0,0,196,195,1,0,0,0,196,
        197,1,0,0,0,197,198,1,0,0,0,198,199,5,39,0,0,199,201,3,22,11,0,200,
        202,3,18,9,0,201,200,1,0,0,0,201,202,1,0,0,0,202,236,1,0,0,0,203,
        204,5,9,0,0,204,205,5,16,0,0,205,214,3,44,22,0,206,208,5,16,0,0,
        207,206,1,0,0,0,207,208,1,0,0,0,208,209,1,0,0,0,209,211,5,41,0,0,
        210,212,5,16,0,0,211,210,1,0,0,0,211,212,1,0,0,0,212,213,1,0,0,0,
        213,215,3,44,22,0,214,207,1,0,0,0,214,215,1,0,0,0,215,216,1,0,0,
        0,216,217,5,16,0,0,217,218,5,10,0,0,218,219,5,16,0,0,219,221,3,26,
        13,0,220,222,5,16,0,0,221,220,1,0,0,0,221,222,1,0,0,0,222,223,1,
        0,0,0,223,224,5,39,0,0,224,225,3,22,11,0,225,236,1,0,0,0,226,227,
        5,11,0,0,227,228,5,16,0,0,228,230,3,30,15,0,229,231,5,16,0,0,230,
        229,1,0,0,0,230,231,1,0,0,0,231,232,1,0,0,0,232,233,5,39,0,0,233,
        234,3,22,11,0,234,236,1,0,0,0,235,192,1,0,0,0,235,203,1,0,0,0,235,
        226,1,0,0,0,236,17,1,0,0,0,237,239,5,8,0,0,238,240,5,16,0,0,239,
        238,1,0,0,0,239,240,1,0,0,0,240,241,1,0,0,0,241,242,5,39,0,0,242,
        243,3,22,11,0,243,19,1,0,0,0,244,245,5,6,0,0,245,246,5,16,0,0,246,
        248,3,44,22,0,247,249,5,16,0,0,248,247,1,0,0,0,248,249,1,0,0,0,249,
        250,1,0,0,0,250,252,5,34,0,0,251,253,3,28,14,0,252,251,1,0,0,0,252,
        253,1,0,0,0,253,254,1,0,0,0,254,256,5,35,0,0,255,257,5,16,0,0,256,
        255,1,0,0,0,256,257,1,0,0,0,257,258,1,0,0,0,258,259,5,39,0,0,259,
        260,3,22,11,0,260,21,1,0,0,0,261,266,5,75,0,0,262,264,3,24,12,0,
        263,265,5,15,0,0,264,263,1,0,0,0,264,265,1,0,0,0,265,267,1,0,0,0,
        266,262,1,0,0,0,267,268,1,0,0,0,268,266,1,0,0,0,268,269,1,0,0,0,
        269,270,1,0,0,0,270,271,5,76,0,0,271,23,1,0,0,0,272,273,5,14,0,0,
        273,274,5,16,0,0,274,277,3,4,2,0,275,277,3,2,1,0,276,272,1,0,0,0,
        276,275,1,0,0,0,277,25,1,0,0,0,278,301,3,48,24,0,279,280,5,1,0,0,
        280,282,5,34,0,0,281,283,5,16,0,0,282,281,1,0,0,0,282,283,1,0,0,
        0,283,284,1,0,0,0,284,286,3,46,23,0,285,287,5,16,0,0,286,285,1,0,
        0,0,286,287,1,0,0,0,287,296,1,0,0,0,288,290,5,41,0,0,289,291,5,16,
        0,0,290,289,1,0,0,0,290,291,1,0,0,0,291,292,1,0,0,0,292,294,3,46,
        23,0,293,295,5,16,0,0,294,293,1,0,0,0,294,295,1,0,0,0,295,297,1,
        0,0,0,296,288,1,0,0,0,296,297,1,0,0,0,297,298,1,0,0,0,298,299,5,
        35,0,0,299,301,1,0,0,0,300,278,1,0,0,0,300,279,1,0,0,0,301,27,1,
        0,0,0,302,313,3,44,22,0,303,305,5,16,0,0,304,303,1,0,0,0,304,305,
        1,0,0,0,305,306,1,0,0,0,306,308,5,41,0,0,307,309,5,16,0,0,308,307,
        1,0,0,0,308,309,1,0,0,0,309,310,1,0,0,0,310,312,3,44,22,0,311,304,
        1,0,0,0,312,315,1,0,0,0,313,311,1,0,0,0,313,314,1,0,0,0,314,29,1,
        0,0,0,315,313,1,0,0,0,316,317,3,4,2,0,317,31,1,0,0,0,318,338,5,55,
        0,0,319,338,5,74,0,0,320,338,5,54,0,0,321,338,5,56,0,0,322,338,5,
        53,0,0,323,338,5,60,0,0,324,338,5,62,0,0,325,338,5,63,0,0,326,338,
        5,65,0,0,327,338,5,64,0,0,328,338,5,66,0,0,329,338,5,67,0,0,330,
        338,5,68,0,0,331,332,5,69,0,0,332,338,5,57,0,0,333,338,5,58,0,0,
        334,338,5,59,0,0,335,338,5,37,0,0,336,338,5,46,0,0,337,318,1,0,0,
        0,337,319,1,0,0,0,337,320,1,0,0,0,337,321,1,0,0,0,337,322,1,0,0,
        0,337,323,1,0,0,0,337,324,1,0,0,0,337,325,1,0,0,0,337,326,1,0,0,
        0,337,327,1,0,0,0,337,328,1,0,0,0,337,329,1,0,0,0,337,330,1,0,0,
        0,337,331,1,0,0,0,337,333,1,0,0,0,337,334,1,0,0,0,337,335,1,0,0,
        0,337,336,1,0,0,0,338,33,1,0,0,0,339,341,3,44,22,0,340,342,5,16,
        0,0,341,340,1,0,0,0,341,342,1,0,0,0,342,343,1,0,0,0,343,345,5,34,
        0,0,344,346,5,16,0,0,345,344,1,0,0,0,345,346,1,0,0,0,346,350,1,0,
        0,0,347,349,3,36,18,0,348,347,1,0,0,0,349,352,1,0,0,0,350,348,1,
        0,0,0,350,351,1,0,0,0,351,353,1,0,0,0,352,350,1,0,0,0,353,354,5,
        35,0,0,354,35,1,0,0,0,355,363,3,38,19,0,356,363,3,52,26,0,357,363,
        3,60,30,0,358,359,5,34,0,0,359,360,3,36,18,0,360,361,5,35,0,0,361,
        363,1,0,0,0,362,355,1,0,0,0,362,356,1,0,0,0,362,357,1,0,0,0,362,
        358,1,0,0,0,363,364,1,0,0,0,364,362,1,0,0,0,364,365,1,0,0,0,365,
        37,1,0,0,0,366,367,7,1,0,0,367,368,5,45,0,0,368,389,3,44,22,0,369,
        389,5,26,0,0,370,371,5,25,0,0,371,373,5,47,0,0,372,374,5,16,0,0,
        373,372,1,0,0,0,373,374,1,0,0,0,374,375,1,0,0,0,375,384,3,46,23,
        0,376,378,5,16,0,0,377,376,1,0,0,0,377,378,1,0,0,0,378,379,1,0,0,
        0,379,381,5,33,0,0,380,382,5,16,0,0,381,380,1,0,0,0,381,382,1,0,
        0,0,382,383,1,0,0,0,383,385,5,18,0,0,384,377,1,0,0,0,384,385,1,0,
        0,0,385,386,1,0,0,0,386,387,5,48,0,0,387,389,1,0,0,0,388,366,1,0,
        0,0,388,369,1,0,0,0,388,370,1,0,0,0,389,39,1,0,0,0,390,396,3,44,
        22,0,391,395,3,52,26,0,392,395,3,60,30,0,393,395,3,38,19,0,394,391,
        1,0,0,0,394,392,1,0,0,0,394,393,1,0,0,0,395,398,1,0,0,0,396,394,
        1,0,0,0,396,397,1,0,0,0,397,41,1,0,0,0,398,396,1,0,0,0,399,402,3,
        44,22,0,400,402,3,46,23,0,401,399,1,0,0,0,401,400,1,0,0,0,402,43,
        1,0,0,0,403,409,5,20,0,0,404,409,5,73,0,0,405,406,3,50,25,0,406,
        407,5,73,0,0,407,409,1,0,0,0,408,403,1,0,0,0,408,404,1,0,0,0,408,
        405,1,0,0,0,409,416,1,0,0,0,410,415,5,20,0,0,411,415,5,18,0,0,412,
        415,5,73,0,0,413,415,3,50,25,0,414,410,1,0,0,0,414,411,1,0,0,0,414,
        412,1,0,0,0,414,413,1,0,0,0,415,418,1,0,0,0,416,414,1,0,0,0,416,
        417,1,0,0,0,417,45,1,0,0,0,418,416,1,0,0,0,419,420,7,2,0,0,420,47,
        1,0,0,0,421,422,6,24,-1,0,422,495,3,44,22,0,423,425,7,3,0,0,424,
        423,1,0,0,0,424,425,1,0,0,0,425,426,1,0,0,0,426,495,5,18,0,0,427,
        495,5,17,0,0,428,495,5,12,0,0,429,495,3,38,19,0,430,432,5,47,0,0,
        431,433,5,16,0,0,432,431,1,0,0,0,432,433,1,0,0,0,433,434,1,0,0,0,
        434,445,3,48,24,0,435,437,5,16,0,0,436,435,1,0,0,0,436,437,1,0,0,
        0,437,438,1,0,0,0,438,440,5,41,0,0,439,441,5,16,0,0,440,439,1,0,
        0,0,440,441,1,0,0,0,441,442,1,0,0,0,442,444,3,48,24,0,443,436,1,
        0,0,0,444,447,1,0,0,0,445,443,1,0,0,0,445,446,1,0,0,0,446,449,1,
        0,0,0,447,445,1,0,0,0,448,450,5,16,0,0,449,448,1,0,0,0,449,450,1,
        0,0,0,450,451,1,0,0,0,451,452,5,48,0,0,452,495,1,0,0,0,453,455,5,
        49,0,0,454,456,5,16,0,0,455,454,1,0,0,0,455,456,1,0,0,0,456,485,
        1,0,0,0,457,459,5,27,0,0,458,460,5,16,0,0,459,458,1,0,0,0,459,460,
        1,0,0,0,460,461,1,0,0,0,461,463,5,39,0,0,462,464,5,16,0,0,463,462,
        1,0,0,0,463,464,1,0,0,0,464,465,1,0,0,0,465,467,3,48,24,0,466,468,
        5,16,0,0,467,466,1,0,0,0,467,468,1,0,0,0,468,469,1,0,0,0,469,471,
        5,41,0,0,470,472,5,16,0,0,471,470,1,0,0,0,471,472,1,0,0,0,472,473,
        1,0,0,0,473,475,5,27,0,0,474,476,5,16,0,0,475,474,1,0,0,0,475,476,
        1,0,0,0,476,477,1,0,0,0,477,479,5,39,0,0,478,480,5,16,0,0,479,478,
        1,0,0,0,479,480,1,0,0,0,480,481,1,0,0,0,481,482,3,48,24,0,482,484,
        1,0,0,0,483,457,1,0,0,0,484,487,1,0,0,0,485,483,1,0,0,0,485,486,
        1,0,0,0,486,489,1,0,0,0,487,485,1,0,0,0,488,490,5,16,0,0,489,488,
        1,0,0,0,489,490,1,0,0,0,490,491,1,0,0,0,491,495,5,50,0,0,492,495,
        5,27,0,0,493,495,5,30,0,0,494,421,1,0,0,0,494,424,1,0,0,0,494,427,
        1,0,0,0,494,428,1,0,0,0,494,429,1,0,0,0,494,430,1,0,0,0,494,453,
        1,0,0,0,494,492,1,0,0,0,494,493,1,0,0,0,495,562,1,0,0,0,496,497,
        10,8,0,0,497,498,5,45,0,0,498,561,3,44,22,0,499,500,10,7,0,0,500,
        502,5,47,0,0,501,503,5,16,0,0,502,501,1,0,0,0,502,503,1,0,0,0,503,
        504,1,0,0,0,504,506,3,42,21,0,505,507,5,16,0,0,506,505,1,0,0,0,506,
        507,1,0,0,0,507,508,1,0,0,0,508,509,5,48,0,0,509,561,1,0,0,0,510,
        511,10,6,0,0,511,513,5,47,0,0,512,514,5,16,0,0,513,512,1,0,0,0,513,
        514,1,0,0,0,514,516,1,0,0,0,515,517,5,74,0,0,516,515,1,0,0,0,516,
        517,1,0,0,0,517,518,1,0,0,0,518,520,3,46,23,0,519,521,5,16,0,0,520,
        519,1,0,0,0,520,521,1,0,0,0,521,522,1,0,0,0,522,524,5,39,0,0,523,
        525,5,16,0,0,524,523,1,0,0,0,524,525,1,0,0,0,525,527,1,0,0,0,526,
        528,5,74,0,0,527,526,1,0,0,0,527,528,1,0,0,0,528,529,1,0,0,0,529,
        531,3,46,23,0,530,532,5,16,0,0,531,530,1,0,0,0,531,532,1,0,0,0,532,
        533,1,0,0,0,533,534,5,48,0,0,534,561,1,0,0,0,535,536,10,5,0,0,536,
        538,5,47,0,0,537,539,5,16,0,0,538,537,1,0,0,0,538,539,1,0,0,0,539,
        541,1,0,0,0,540,542,5,74,0,0,541,540,1,0,0,0,541,542,1,0,0,0,542,
        543,1,0,0,0,543,545,3,46,23,0,544,546,5,16,0,0,545,544,1,0,0,0,545,
        546,1,0,0,0,546,547,1,0,0,0,547,549,5,33,0,0,548,550,5,16,0,0,549,
        548,1,0,0,0,549,550,1,0,0,0,550,552,1,0,0,0,551,553,5,74,0,0,552,
        551,1,0,0,0,552,553,1,0,0,0,553,554,1,0,0,0,554,556,5,18,0,0,555,
        557,5,16,0,0,556,555,1,0,0,0,556,557,1,0,0,0,557,558,1,0,0,0,558,
        559,5,48,0,0,559,561,1,0,0,0,560,496,1,0,0,0,560,499,1,0,0,0,560,
        510,1,0,0,0,560,535,1,0,0,0,561,564,1,0,0,0,562,560,1,0,0,0,562,
        563,1,0,0,0,563,49,1,0,0,0,564,562,1,0,0,0,565,566,7,4,0,0,566,51,
        1,0,0,0,567,571,3,54,27,0,568,571,3,56,28,0,569,571,3,58,29,0,570,
        567,1,0,0,0,570,568,1,0,0,0,570,569,1,0,0,0,571,53,1,0,0,0,572,573,
        5,38,0,0,573,574,5,34,0,0,574,575,3,40,20,0,575,576,5,35,0,0,576,
        55,1,0,0,0,577,578,5,37,0,0,578,579,5,34,0,0,579,580,3,4,2,0,580,
        581,5,35,0,0,581,57,1,0,0,0,582,583,5,36,0,0,583,584,5,34,0,0,584,
        585,3,36,18,0,585,586,5,35,0,0,586,59,1,0,0,0,587,596,5,20,0,0,588,
        596,5,18,0,0,589,596,3,62,31,0,590,596,5,27,0,0,591,592,5,34,0,0,
        592,593,3,60,30,0,593,594,5,35,0,0,594,596,1,0,0,0,595,587,1,0,0,
        0,595,588,1,0,0,0,595,589,1,0,0,0,595,590,1,0,0,0,595,591,1,0,0,
        0,596,61,1,0,0,0,597,598,7,5,0,0,598,63,1,0,0,0,99,67,73,75,78,95,
        98,105,110,115,119,123,127,131,135,141,145,154,158,162,165,169,172,
        176,190,196,201,207,211,214,221,230,235,239,248,252,256,264,268,
        276,282,286,290,294,296,300,304,308,313,337,341,345,350,362,364,
        373,377,381,384,388,394,396,401,408,414,416,424,432,436,440,445,
        449,455,459,463,467,471,475,479,485,489,494,502,506,513,516,520,
        524,527,531,538,541,545,549,552,556,560,562,570,595
    ]

class dAngrParser ( Parser ):

    grammarFileName = "dAngr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'range'", "'static'", "'IIF'", "'THEN'", 
                     "'ELSE'", "'def'", "'if'", "'else'", "'for'", "'in'", 
                     "'while'", "<INVALID>", "'help'", "'return'", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "'&sym'", "'&reg'", "'&vars'", 
                     "'&mem'", "'&state'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "'->'", "'('", 
                     "')'", "'!'", "'&'", "'$'", "':'", "';'", "','", "'\"'", 
                     "'''", "'@'", "'.'", "'|'", "'['", "']'", "'{'", "'}'", 
                     "'^'", "'#'", "'%'", "'*'", "'+'", "'/'", "'//'", "'<<'", 
                     "'>>'", "'**'", "'='", "'=='", "'!='", "'<'", "'>'", 
                     "'<='", "'>='", "'&&'", "'||'", "'?'", "'~'", "'`'", 
                     "'_'", "'-'" ]

    symbolicNames = [ "<INVALID>", "<INVALID>", "STATIC", "CIF", "CTHEN", 
                      "CELSE", "DEF", "IF", "ELSE", "FOR", "IN", "WHILE", 
                      "BOOL", "HELP", "RETURN", "NEWLINE", "WS", "HEX_NUMBERS", 
                      "NUMBERS", "NUMBER", "LETTERS", "LETTER", "SYM_DB", 
                      "REG_DB", "VARS_DB", "MEM_DB", "STATE", "STRING", 
                      "ESCAPED_QUOTE", "ESCAPED_SINGLE_QUOTE", "BINARY_STRING", 
                      "SESC_SEQ", "ESC_SEQ", "ARROW", "LPAREN", "RPAREN", 
                      "BANG", "AMP", "DOLLAR", "COLON", "SCOLON", "COMMA", 
                      "QUOTE", "SQUOTE", "AT", "DOT", "BAR", "BRA", "KET", 
                      "BRACE", "KETCE", "HAT", "HASH", "PERC", "MUL", "ADD", 
                      "DIV", "FLOORDIV", "LSHIFT", "RSHIFT", "POW", "ASSIGN", 
                      "EQ", "NEQ", "LT", "GT", "LE", "GE", "AND", "OR", 
                      "QMARK", "TILDE", "TICK", "UNDERSCORE", "DASH", "INDENT", 
                      "DEDENT" ]

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
    RULE_fstatement = 12
    RULE_iterable = 13
    RULE_parameters = 14
    RULE_condition = 15
    RULE_operation = 16
    RULE_py_basic_content = 17
    RULE_py_content = 18
    RULE_reference = 19
    RULE_bash_content = 20
    RULE_index = 21
    RULE_identifier = 22
    RULE_numeric = 23
    RULE_object = 24
    RULE_special_words = 25
    RULE_range = 26
    RULE_bash_range = 27
    RULE_dangr_range = 28
    RULE_python_range = 29
    RULE_anything = 30
    RULE_symbol = 31

    ruleNames =  [ "script", "statement", "expression", "constraint", "expression_part", 
                   "assignment", "static_var", "ext_command", "control_flow", 
                   "else_", "function_def", "body", "fstatement", "iterable", 
                   "parameters", "condition", "operation", "py_basic_content", 
                   "py_content", "reference", "bash_content", "index", "identifier", 
                   "numeric", "object", "special_words", "range", "bash_range", 
                   "dangr_range", "python_range", "anything", "symbol" ]

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
    RETURN=14
    NEWLINE=15
    WS=16
    HEX_NUMBERS=17
    NUMBERS=18
    NUMBER=19
    LETTERS=20
    LETTER=21
    SYM_DB=22
    REG_DB=23
    VARS_DB=24
    MEM_DB=25
    STATE=26
    STRING=27
    ESCAPED_QUOTE=28
    ESCAPED_SINGLE_QUOTE=29
    BINARY_STRING=30
    SESC_SEQ=31
    ESC_SEQ=32
    ARROW=33
    LPAREN=34
    RPAREN=35
    BANG=36
    AMP=37
    DOLLAR=38
    COLON=39
    SCOLON=40
    COMMA=41
    QUOTE=42
    SQUOTE=43
    AT=44
    DOT=45
    BAR=46
    BRA=47
    KET=48
    BRACE=49
    KETCE=50
    HAT=51
    HASH=52
    PERC=53
    MUL=54
    ADD=55
    DIV=56
    FLOORDIV=57
    LSHIFT=58
    RSHIFT=59
    POW=60
    ASSIGN=61
    EQ=62
    NEQ=63
    LT=64
    GT=65
    LE=66
    GE=67
    AND=68
    OR=69
    QMARK=70
    TILDE=71
    TICK=72
    UNDERSCORE=73
    DASH=74
    INDENT=75
    DEDENT=76

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
            self.state = 78
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,3,self._ctx)
            if la_ == 1:
                self.state = 64
                _la = self._input.LA(1)
                if not(_la==13 or _la==70):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 67
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 65
                    self.match(dAngrParser.WS)
                    self.state = 66
                    self.identifier()


                self.state = 69
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 2:
                self.state = 75
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while (((_la) & ~0x3f) == 0 and ((1 << _la) & 108790578054365180) != 0) or _la==73 or _la==74:
                    self.state = 73
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
                    if la_ == 1:
                        self.state = 70
                        self.match(dAngrParser.NEWLINE)
                        pass

                    elif la_ == 2:
                        self.state = 71
                        self.statement()
                        pass

                    elif la_ == 3:
                        self.state = 72
                        self.function_def()
                        pass


                    self.state = 77
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                pass


            self.state = 80
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
            self.state = 95
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,4,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 82
                self.control_flow()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 83
                self.assignment()
                self.state = 84
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 86
                self.expression()
                self.state = 87
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 89
                self.static_var()
                self.state = 90
                self.match(dAngrParser.NEWLINE)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 92
                self.ext_command()
                self.state = 93
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


        def DIV(self):
            return self.getToken(dAngrParser.DIV, 0)

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
        self._la = 0 # Token type
        try:
            self.state = 115
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,8,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 98
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==56:
                    self.state = 97
                    self.match(dAngrParser.DIV)


                self.state = 100
                self.identifier()
                self.state = 110
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,7,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 101
                        self.match(dAngrParser.WS)
                        self.state = 105
                        self._errHandler.sync(self)
                        la_ = self._interp.adaptivePredict(self._input,6,self._ctx)
                        if la_ == 1:
                            self.state = 102
                            self.identifier()
                            self.state = 103
                            self.match(dAngrParser.ASSIGN)


                        self.state = 107
                        self.expression_part() 
                    self.state = 112
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,7,self._ctx)

                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 113
                self.constraint()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 114
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
            self.state = 117
            self.match(dAngrParser.CIF)
            self.state = 119
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 118
                self.match(dAngrParser.WS)


            self.state = 121
            self.condition()
            self.state = 123
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 122
                self.match(dAngrParser.WS)


            self.state = 125
            self.match(dAngrParser.CTHEN)
            self.state = 127
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 126
                self.match(dAngrParser.WS)


            self.state = 129
            self.expression_part()
            self.state = 131
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 130
                self.match(dAngrParser.WS)


            self.state = 133
            self.match(dAngrParser.CELSE)
            self.state = 135
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 134
                self.match(dAngrParser.WS)


            self.state = 137
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


        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

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
            self.state = 165
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 139
                self.match(dAngrParser.LPAREN)
                self.state = 141
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 140
                    self.match(dAngrParser.WS)


                self.state = 143
                self.expression()
                self.state = 145
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 144
                    self.match(dAngrParser.WS)


                self.state = 147
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 149
                self.range_()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 150
                self.reference()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 151
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 152
                self.object_(0)
                self.state = 162
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,18,self._ctx)
                if la_ == 1:
                    self.state = 154
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 153
                        self.match(dAngrParser.WS)


                    self.state = 156
                    self.operation()
                    self.state = 158
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 157
                        self.match(dAngrParser.WS)


                    self.state = 160
                    self.expression()


                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 164
                self.object_(0)
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
            self.state = 169
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,20,self._ctx)
            if la_ == 1:
                self.state = 167
                self.static_var()
                pass

            elif la_ == 2:
                self.state = 168
                self.object_(0)
                pass


            self.state = 172
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 171
                self.match(dAngrParser.WS)


            self.state = 174
            self.match(dAngrParser.ASSIGN)
            self.state = 176
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 175
                self.match(dAngrParser.WS)


            self.state = 178
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
            self.state = 180
            self.match(dAngrParser.STATIC)
            self.state = 181
            self.match(dAngrParser.WS)
            self.state = 182
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
            self.state = 190
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [36]:
                self.enterOuterAlt(localctx, 1)
                self.state = 184
                self.match(dAngrParser.BANG)
                self.state = 185
                self.py_basic_content()
                pass
            elif token in [37]:
                self.enterOuterAlt(localctx, 2)
                self.state = 186
                self.match(dAngrParser.AMP)
                self.state = 187
                self.expression()
                pass
            elif token in [38]:
                self.enterOuterAlt(localctx, 3)
                self.state = 188
                self.match(dAngrParser.DOLLAR)
                self.state = 189
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
            self.state = 235
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [7]:
                self.enterOuterAlt(localctx, 1)
                self.state = 192
                self.match(dAngrParser.IF)
                self.state = 193
                self.match(dAngrParser.WS)
                self.state = 194
                self.condition()
                self.state = 196
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 195
                    self.match(dAngrParser.WS)


                self.state = 198
                self.match(dAngrParser.COLON)
                self.state = 199
                self.body()
                self.state = 201
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,25,self._ctx)
                if la_ == 1:
                    self.state = 200
                    self.else_()


                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 2)
                self.state = 203
                self.match(dAngrParser.FOR)
                self.state = 204
                self.match(dAngrParser.WS)
                self.state = 205
                self.identifier()
                self.state = 214
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,28,self._ctx)
                if la_ == 1:
                    self.state = 207
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 206
                        self.match(dAngrParser.WS)


                    self.state = 209
                    self.match(dAngrParser.COMMA)
                    self.state = 211
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 210
                        self.match(dAngrParser.WS)


                    self.state = 213
                    self.identifier()


                self.state = 216
                self.match(dAngrParser.WS)
                self.state = 217
                self.match(dAngrParser.IN)
                self.state = 218
                self.match(dAngrParser.WS)
                self.state = 219
                self.iterable()
                self.state = 221
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 220
                    self.match(dAngrParser.WS)


                self.state = 223
                self.match(dAngrParser.COLON)
                self.state = 224
                self.body()
                pass
            elif token in [11]:
                self.enterOuterAlt(localctx, 3)
                self.state = 226
                self.match(dAngrParser.WHILE)
                self.state = 227
                self.match(dAngrParser.WS)
                self.state = 228
                self.condition()
                self.state = 230
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 229
                    self.match(dAngrParser.WS)


                self.state = 232
                self.match(dAngrParser.COLON)
                self.state = 233
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
            self.state = 237
            self.match(dAngrParser.ELSE)
            self.state = 239
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 238
                self.match(dAngrParser.WS)


            self.state = 241
            self.match(dAngrParser.COLON)
            self.state = 242
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
            self.state = 244
            self.match(dAngrParser.DEF)
            self.state = 245
            self.match(dAngrParser.WS)
            self.state = 246
            self.identifier()
            self.state = 248
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 247
                self.match(dAngrParser.WS)


            self.state = 250
            self.match(dAngrParser.LPAREN)
            self.state = 252
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if (((_la) & ~0x3f) == 0 and ((1 << _la) & 1081340) != 0) or _la==73:
                self.state = 251
                self.parameters()


            self.state = 254
            self.match(dAngrParser.RPAREN)
            self.state = 256
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 255
                self.match(dAngrParser.WS)


            self.state = 258
            self.match(dAngrParser.COLON)
            self.state = 259
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

        def fstatement(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.FstatementContext)
            else:
                return self.getTypedRuleContext(dAngrParser.FstatementContext,i)


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
            self.state = 261
            self.match(dAngrParser.INDENT)
            self.state = 266 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 262
                self.fstatement()
                self.state = 264
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==15:
                    self.state = 263
                    self.match(dAngrParser.NEWLINE)


                self.state = 268 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 108790578054332412) != 0) or _la==73 or _la==74):
                    break

            self.state = 270
            self.match(dAngrParser.DEDENT)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class FstatementContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def RETURN(self):
            return self.getToken(dAngrParser.RETURN, 0)

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def statement(self):
            return self.getTypedRuleContext(dAngrParser.StatementContext,0)


        def getRuleIndex(self):
            return dAngrParser.RULE_fstatement

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFstatement" ):
                listener.enterFstatement(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFstatement" ):
                listener.exitFstatement(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFstatement" ):
                return visitor.visitFstatement(self)
            else:
                return visitor.visitChildren(self)




    def fstatement(self):

        localctx = dAngrParser.FstatementContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_fstatement)
        try:
            self.state = 276
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,38,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 272
                self.match(dAngrParser.RETURN)
                self.state = 273
                self.match(dAngrParser.WS)
                self.state = 274
                self.expression()
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 275
                self.statement()
                pass


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
        self.enterRule(localctx, 26, self.RULE_iterable)
        self._la = 0 # Token type
        try:
            self.state = 300
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 20, 22, 23, 24, 25, 26, 27, 30, 47, 49, 55, 73, 74]:
                self.enterOuterAlt(localctx, 1)
                self.state = 278
                self.object_(0)
                pass
            elif token in [1]:
                self.enterOuterAlt(localctx, 2)
                self.state = 279
                self.match(dAngrParser.T__0)
                self.state = 280
                self.match(dAngrParser.LPAREN)
                self.state = 282
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 281
                    self.match(dAngrParser.WS)


                self.state = 284
                self.numeric()
                self.state = 286
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 285
                    self.match(dAngrParser.WS)


                self.state = 296
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==41:
                    self.state = 288
                    self.match(dAngrParser.COMMA)
                    self.state = 290
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 289
                        self.match(dAngrParser.WS)


                    self.state = 292
                    self.numeric()
                    self.state = 294
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 293
                        self.match(dAngrParser.WS)




                self.state = 298
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
        self.enterRule(localctx, 28, self.RULE_parameters)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 302
            self.identifier()
            self.state = 313
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==16 or _la==41:
                self.state = 304
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 303
                    self.match(dAngrParser.WS)


                self.state = 306
                self.match(dAngrParser.COMMA)
                self.state = 308
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 307
                    self.match(dAngrParser.WS)


                self.state = 310
                self.identifier()
                self.state = 315
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
        self.enterRule(localctx, 30, self.RULE_condition)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 316
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

        def MUL(self):
            return self.getToken(dAngrParser.MUL, 0)

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

        def FLOORDIV(self):
            return self.getToken(dAngrParser.FLOORDIV, 0)

        def LSHIFT(self):
            return self.getToken(dAngrParser.LSHIFT, 0)

        def RSHIFT(self):
            return self.getToken(dAngrParser.RSHIFT, 0)

        def AMP(self):
            return self.getToken(dAngrParser.AMP, 0)

        def BAR(self):
            return self.getToken(dAngrParser.BAR, 0)

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
        self.enterRule(localctx, 32, self.RULE_operation)
        try:
            self.state = 337
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [55]:
                self.enterOuterAlt(localctx, 1)
                self.state = 318
                self.match(dAngrParser.ADD)
                pass
            elif token in [74]:
                self.enterOuterAlt(localctx, 2)
                self.state = 319
                self.match(dAngrParser.DASH)
                pass
            elif token in [54]:
                self.enterOuterAlt(localctx, 3)
                self.state = 320
                self.match(dAngrParser.MUL)
                pass
            elif token in [56]:
                self.enterOuterAlt(localctx, 4)
                self.state = 321
                self.match(dAngrParser.DIV)
                pass
            elif token in [53]:
                self.enterOuterAlt(localctx, 5)
                self.state = 322
                self.match(dAngrParser.PERC)
                pass
            elif token in [60]:
                self.enterOuterAlt(localctx, 6)
                self.state = 323
                self.match(dAngrParser.POW)
                pass
            elif token in [62]:
                self.enterOuterAlt(localctx, 7)
                self.state = 324
                self.match(dAngrParser.EQ)
                pass
            elif token in [63]:
                self.enterOuterAlt(localctx, 8)
                self.state = 325
                self.match(dAngrParser.NEQ)
                pass
            elif token in [65]:
                self.enterOuterAlt(localctx, 9)
                self.state = 326
                self.match(dAngrParser.GT)
                pass
            elif token in [64]:
                self.enterOuterAlt(localctx, 10)
                self.state = 327
                self.match(dAngrParser.LT)
                pass
            elif token in [66]:
                self.enterOuterAlt(localctx, 11)
                self.state = 328
                self.match(dAngrParser.LE)
                pass
            elif token in [67]:
                self.enterOuterAlt(localctx, 12)
                self.state = 329
                self.match(dAngrParser.GE)
                pass
            elif token in [68]:
                self.enterOuterAlt(localctx, 13)
                self.state = 330
                self.match(dAngrParser.AND)
                pass
            elif token in [69]:
                self.enterOuterAlt(localctx, 14)
                self.state = 331
                self.match(dAngrParser.OR)
                self.state = 332
                self.match(dAngrParser.FLOORDIV)
                pass
            elif token in [58]:
                self.enterOuterAlt(localctx, 15)
                self.state = 333
                self.match(dAngrParser.LSHIFT)
                pass
            elif token in [59]:
                self.enterOuterAlt(localctx, 16)
                self.state = 334
                self.match(dAngrParser.RSHIFT)
                pass
            elif token in [37]:
                self.enterOuterAlt(localctx, 17)
                self.state = 335
                self.match(dAngrParser.AMP)
                pass
            elif token in [46]:
                self.enterOuterAlt(localctx, 18)
                self.state = 336
                self.match(dAngrParser.BAR)
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
        self.enterRule(localctx, 34, self.RULE_py_basic_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 339
            self.identifier()
            self.state = 341
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==16:
                self.state = 340
                self.match(dAngrParser.WS)


            self.state = 343
            self.match(dAngrParser.LPAREN)
            self.state = 345
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,50,self._ctx)
            if la_ == 1:
                self.state = 344
                self.match(dAngrParser.WS)


            self.state = 350
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 16)) & ~0x3f) == 0 and ((1 << (_la - 16)) & 576460752302641109) != 0):
                self.state = 347
                self.py_content()
                self.state = 352
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 353
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
        self.enterRule(localctx, 36, self.RULE_py_content)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 362 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 362
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,52,self._ctx)
                    if la_ == 1:
                        self.state = 355
                        self.reference()
                        pass

                    elif la_ == 2:
                        self.state = 356
                        self.range_()
                        pass

                    elif la_ == 3:
                        self.state = 357
                        self.anything()
                        pass

                    elif la_ == 4:
                        self.state = 358
                        self.match(dAngrParser.LPAREN)
                        self.state = 359
                        self.py_content()
                        self.state = 360
                        self.match(dAngrParser.RPAREN)
                        pass



                else:
                    raise NoViableAltException(self)
                self.state = 364 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,53,self._ctx)

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
        self.enterRule(localctx, 38, self.RULE_reference)
        self._la = 0 # Token type
        try:
            self.state = 388
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [22, 23, 24]:
                self.enterOuterAlt(localctx, 1)
                self.state = 366
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 29360128) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 367
                self.match(dAngrParser.DOT)
                self.state = 368
                self.identifier()
                pass
            elif token in [26]:
                self.enterOuterAlt(localctx, 2)
                self.state = 369
                self.match(dAngrParser.STATE)
                pass
            elif token in [25]:
                self.enterOuterAlt(localctx, 3)
                self.state = 370
                self.match(dAngrParser.MEM_DB)
                self.state = 371
                self.match(dAngrParser.BRA)
                self.state = 373
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 372
                    self.match(dAngrParser.WS)


                self.state = 375
                self.numeric()
                self.state = 384
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16 or _la==33:
                    self.state = 377
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 376
                        self.match(dAngrParser.WS)


                    self.state = 379
                    self.match(dAngrParser.ARROW)
                    self.state = 381
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 380
                        self.match(dAngrParser.WS)


                    self.state = 383
                    self.match(dAngrParser.NUMBERS)


                self.state = 386
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
        self.enterRule(localctx, 40, self.RULE_bash_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 390
            self.identifier()
            self.state = 396
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 16)) & ~0x3f) == 0 and ((1 << (_la - 16)) & 576460752302641109) != 0):
                self.state = 394
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,59,self._ctx)
                if la_ == 1:
                    self.state = 391
                    self.range_()
                    pass

                elif la_ == 2:
                    self.state = 392
                    self.anything()
                    pass

                elif la_ == 3:
                    self.state = 393
                    self.reference()
                    pass


                self.state = 398
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
        self.enterRule(localctx, 42, self.RULE_index)
        try:
            self.state = 401
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 20, 73]:
                self.enterOuterAlt(localctx, 1)
                self.state = 399
                self.identifier()
                pass
            elif token in [17, 18]:
                self.enterOuterAlt(localctx, 2)
                self.state = 400
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
        self.enterRule(localctx, 44, self.RULE_identifier)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 408
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [20]:
                self.state = 403
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [73]:
                self.state = 404
                self.match(dAngrParser.UNDERSCORE)
                pass
            elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:
                self.state = 405
                self.special_words()
                self.state = 406
                self.match(dAngrParser.UNDERSCORE)
                pass
            else:
                raise NoViableAltException(self)

            self.state = 416
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,64,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 414
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [20]:
                        self.state = 410
                        self.match(dAngrParser.LETTERS)
                        pass
                    elif token in [18]:
                        self.state = 411
                        self.match(dAngrParser.NUMBERS)
                        pass
                    elif token in [73]:
                        self.state = 412
                        self.match(dAngrParser.UNDERSCORE)
                        pass
                    elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:
                        self.state = 413
                        self.special_words()
                        pass
                    else:
                        raise NoViableAltException(self)
             
                self.state = 418
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,64,self._ctx)

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
        self.enterRule(localctx, 46, self.RULE_numeric)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 419
            _la = self._input.LA(1)
            if not(_la==17 or _la==18):
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

        def DASH(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.DASH)
            else:
                return self.getToken(dAngrParser.DASH, i)

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
        _startState = 48
        self.enterRecursionRule(localctx, 48, self.RULE_object, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 494
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,80,self._ctx)
            if la_ == 1:
                self.state = 422
                self.identifier()
                pass

            elif la_ == 2:
                self.state = 424
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==55 or _la==74:
                    self.state = 423
                    _la = self._input.LA(1)
                    if not(_la==55 or _la==74):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()


                self.state = 426
                self.match(dAngrParser.NUMBERS)
                pass

            elif la_ == 3:
                self.state = 427
                self.match(dAngrParser.HEX_NUMBERS)
                pass

            elif la_ == 4:
                self.state = 428
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 5:
                self.state = 429
                self.reference()
                pass

            elif la_ == 6:
                self.state = 430
                self.match(dAngrParser.BRA)
                self.state = 432
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 431
                    self.match(dAngrParser.WS)


                self.state = 434
                self.object_(0)
                self.state = 445
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,69,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 436
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 435
                            self.match(dAngrParser.WS)


                        self.state = 438
                        self.match(dAngrParser.COMMA)
                        self.state = 440
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 439
                            self.match(dAngrParser.WS)


                        self.state = 442
                        self.object_(0) 
                    self.state = 447
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,69,self._ctx)

                self.state = 449
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 448
                    self.match(dAngrParser.WS)


                self.state = 451
                self.match(dAngrParser.KET)
                pass

            elif la_ == 7:
                self.state = 453
                self.match(dAngrParser.BRACE)
                self.state = 455
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,71,self._ctx)
                if la_ == 1:
                    self.state = 454
                    self.match(dAngrParser.WS)


                self.state = 485
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==27:
                    self.state = 457
                    self.match(dAngrParser.STRING)
                    self.state = 459
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 458
                        self.match(dAngrParser.WS)


                    self.state = 461
                    self.match(dAngrParser.COLON)
                    self.state = 463
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 462
                        self.match(dAngrParser.WS)


                    self.state = 465
                    self.object_(0)

                    self.state = 467
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 466
                        self.match(dAngrParser.WS)


                    self.state = 469
                    self.match(dAngrParser.COMMA)
                    self.state = 471
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 470
                        self.match(dAngrParser.WS)


                    self.state = 473
                    self.match(dAngrParser.STRING)
                    self.state = 475
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 474
                        self.match(dAngrParser.WS)


                    self.state = 477
                    self.match(dAngrParser.COLON)
                    self.state = 479
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==16:
                        self.state = 478
                        self.match(dAngrParser.WS)


                    self.state = 481
                    self.object_(0)
                    self.state = 487
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 489
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==16:
                    self.state = 488
                    self.match(dAngrParser.WS)


                self.state = 491
                self.match(dAngrParser.KETCE)
                pass

            elif la_ == 8:
                self.state = 492
                self.match(dAngrParser.STRING)
                pass

            elif la_ == 9:
                self.state = 493
                self.match(dAngrParser.BINARY_STRING)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 562
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,96,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 560
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,95,self._ctx)
                    if la_ == 1:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 496
                        if not self.precpred(self._ctx, 8):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 8)")
                        self.state = 497
                        self.match(dAngrParser.DOT)
                        self.state = 498
                        self.identifier()
                        pass

                    elif la_ == 2:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 499
                        if not self.precpred(self._ctx, 7):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 7)")
                        self.state = 500
                        self.match(dAngrParser.BRA)
                        self.state = 502
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 501
                            self.match(dAngrParser.WS)


                        self.state = 504
                        self.index()
                        self.state = 506
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 505
                            self.match(dAngrParser.WS)


                        self.state = 508
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 3:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 510
                        if not self.precpred(self._ctx, 6):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                        self.state = 511
                        self.match(dAngrParser.BRA)
                        self.state = 513
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 512
                            self.match(dAngrParser.WS)


                        self.state = 516
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==74:
                            self.state = 515
                            self.match(dAngrParser.DASH)


                        self.state = 518
                        self.numeric()
                        self.state = 520
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 519
                            self.match(dAngrParser.WS)


                        self.state = 522
                        self.match(dAngrParser.COLON)
                        self.state = 524
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 523
                            self.match(dAngrParser.WS)


                        self.state = 527
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==74:
                            self.state = 526
                            self.match(dAngrParser.DASH)


                        self.state = 529
                        self.numeric()
                        self.state = 531
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 530
                            self.match(dAngrParser.WS)


                        self.state = 533
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 4:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 535
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 536
                        self.match(dAngrParser.BRA)
                        self.state = 538
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 537
                            self.match(dAngrParser.WS)


                        self.state = 541
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==74:
                            self.state = 540
                            self.match(dAngrParser.DASH)


                        self.state = 543
                        self.numeric()
                        self.state = 545
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 544
                            self.match(dAngrParser.WS)


                        self.state = 547
                        self.match(dAngrParser.ARROW)
                        self.state = 549
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 548
                            self.match(dAngrParser.WS)


                        self.state = 552
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==74:
                            self.state = 551
                            self.match(dAngrParser.DASH)


                        self.state = 554
                        self.match(dAngrParser.NUMBERS)
                        self.state = 556
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==16:
                            self.state = 555
                            self.match(dAngrParser.WS)


                        self.state = 558
                        self.match(dAngrParser.KET)
                        pass

             
                self.state = 564
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,96,self._ctx)

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

        def RETURN(self):
            return self.getToken(dAngrParser.RETURN, 0)

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
        self.enterRule(localctx, 50, self.RULE_special_words)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 565
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 32764) != 0)):
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
        self.enterRule(localctx, 52, self.RULE_range)
        try:
            self.state = 570
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [38]:
                self.enterOuterAlt(localctx, 1)
                self.state = 567
                self.bash_range()
                pass
            elif token in [37]:
                self.enterOuterAlt(localctx, 2)
                self.state = 568
                self.dangr_range()
                pass
            elif token in [36]:
                self.enterOuterAlt(localctx, 3)
                self.state = 569
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
        self.enterRule(localctx, 54, self.RULE_bash_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 572
            self.match(dAngrParser.DOLLAR)
            self.state = 573
            self.match(dAngrParser.LPAREN)
            self.state = 574
            self.bash_content()
            self.state = 575
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
        self.enterRule(localctx, 56, self.RULE_dangr_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 577
            self.match(dAngrParser.AMP)
            self.state = 578
            self.match(dAngrParser.LPAREN)
            self.state = 579
            self.expression()
            self.state = 580
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
        self.enterRule(localctx, 58, self.RULE_python_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 582
            self.match(dAngrParser.BANG)
            self.state = 583
            self.match(dAngrParser.LPAREN)
            self.state = 584
            self.py_content()
            self.state = 585
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
        self.enterRule(localctx, 60, self.RULE_anything)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 595
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [20]:
                self.state = 587
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [18]:
                self.state = 588
                self.match(dAngrParser.NUMBERS)
                pass
            elif token in [16, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74]:
                self.state = 589
                self.symbol()
                pass
            elif token in [27]:
                self.state = 590
                self.match(dAngrParser.STRING)
                pass
            elif token in [34]:
                self.state = 591
                self.match(dAngrParser.LPAREN)
                self.state = 592
                self.anything()
                self.state = 593
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

        def MUL(self):
            return self.getToken(dAngrParser.MUL, 0)

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

        def FLOORDIV(self):
            return self.getToken(dAngrParser.FLOORDIV, 0)

        def LSHIFT(self):
            return self.getToken(dAngrParser.LSHIFT, 0)

        def RSHIFT(self):
            return self.getToken(dAngrParser.RSHIFT, 0)

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
        self.enterRule(localctx, 62, self.RULE_symbol)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 597
            _la = self._input.LA(1)
            if not(((((_la - 16)) & ~0x3f) == 0 and ((1 << (_la - 16)) & 576460752302374913) != 0)):
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
        self._predicates[24] = self.object_sempred
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
         




