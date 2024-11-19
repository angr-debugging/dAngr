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
        4,1,79,627,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,1,0,1,0,1,0,3,0,66,8,0,1,
        0,1,0,1,0,1,0,5,0,72,8,0,10,0,12,0,75,9,0,3,0,77,8,0,1,0,1,0,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,94,8,1,1,2,1,
        2,1,2,3,2,99,8,2,1,2,3,2,102,8,2,1,2,1,2,1,2,1,2,1,2,3,2,109,8,2,
        1,2,5,2,112,8,2,10,2,12,2,115,9,2,1,2,3,2,118,8,2,1,3,1,3,1,3,3,
        3,123,8,3,1,3,1,3,3,3,127,8,3,1,3,1,3,3,3,131,8,3,1,3,1,3,3,3,135,
        8,3,1,3,1,3,3,3,139,8,3,1,3,1,3,1,3,1,3,3,3,145,8,3,1,3,1,3,3,3,
        149,8,3,1,3,1,3,1,3,1,3,1,3,3,3,156,8,3,1,3,1,3,3,3,160,8,3,1,3,
        1,3,3,3,164,8,3,1,3,1,3,3,3,168,8,3,1,3,1,3,3,3,172,8,3,1,3,1,3,
        3,3,176,8,3,3,3,178,8,3,3,3,180,8,3,1,3,1,3,1,3,1,3,1,3,1,3,1,3,
        3,3,189,8,3,1,3,1,3,3,3,193,8,3,1,3,1,3,1,3,3,3,198,8,3,1,3,1,3,
        1,3,1,3,1,3,5,3,205,8,3,10,3,12,3,208,9,3,1,4,1,4,3,4,212,8,4,1,
        4,3,4,215,8,4,1,4,1,4,3,4,219,8,4,1,4,1,4,1,5,1,5,1,5,1,5,1,6,1,
        6,1,6,1,6,1,6,1,6,3,6,233,8,6,1,7,1,7,1,7,1,7,3,7,239,8,7,1,7,1,
        7,1,7,3,7,244,8,7,1,7,1,7,1,7,1,7,3,7,250,8,7,1,7,1,7,3,7,254,8,
        7,1,7,3,7,257,8,7,1,7,1,7,1,7,1,7,1,7,3,7,264,8,7,1,7,1,7,1,7,1,
        7,1,7,1,7,1,7,3,7,273,8,7,1,7,1,7,1,7,3,7,278,8,7,1,8,1,8,3,8,282,
        8,8,1,8,1,8,1,8,1,9,1,9,1,9,1,9,3,9,291,8,9,1,9,1,9,3,9,295,8,9,
        1,9,1,9,3,9,299,8,9,1,9,1,9,1,9,1,10,1,10,1,10,3,10,307,8,10,4,10,
        309,8,10,11,10,12,10,310,1,10,1,10,1,11,1,11,1,11,1,11,1,11,1,11,
        3,11,321,8,11,1,12,1,12,1,13,1,13,3,13,327,8,13,1,13,1,13,3,13,331,
        8,13,1,13,5,13,334,8,13,10,13,12,13,337,9,13,1,14,1,14,1,15,1,15,
        1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,1,15,
        1,15,1,15,1,15,1,15,3,15,360,8,15,1,16,1,16,3,16,364,8,16,1,16,1,
        16,3,16,368,8,16,1,16,5,16,371,8,16,10,16,12,16,374,9,16,1,16,1,
        16,1,17,1,17,1,17,1,17,1,17,1,17,1,17,4,17,385,8,17,11,17,12,17,
        386,1,18,1,18,1,18,1,18,1,18,1,18,1,18,5,18,396,8,18,10,18,12,18,
        399,9,18,1,19,1,19,1,19,1,19,3,19,405,8,19,1,19,1,19,1,19,1,19,3,
        19,411,8,19,1,19,1,19,3,19,415,8,19,1,19,1,19,3,19,419,8,19,1,19,
        3,19,422,8,19,1,19,1,19,3,19,426,8,19,3,19,428,8,19,1,20,3,20,431,
        8,20,1,20,1,20,1,21,1,21,1,21,1,21,1,21,3,21,440,8,21,1,21,1,21,
        1,21,1,21,5,21,446,8,21,10,21,12,21,449,9,21,1,22,1,22,1,23,1,23,
        1,23,3,23,456,8,23,1,23,3,23,459,8,23,1,23,1,23,1,23,1,23,1,23,3,
        23,466,8,23,1,23,3,23,469,8,23,1,23,3,23,472,8,23,1,23,1,23,3,23,
        476,8,23,1,23,5,23,479,8,23,10,23,12,23,482,9,23,1,23,3,23,485,8,
        23,1,23,1,23,1,23,3,23,490,8,23,1,23,1,23,3,23,494,8,23,1,23,1,23,
        3,23,498,8,23,1,23,1,23,3,23,502,8,23,1,23,1,23,3,23,506,8,23,1,
        23,1,23,3,23,510,8,23,1,23,1,23,3,23,514,8,23,1,23,1,23,5,23,518,
        8,23,10,23,12,23,521,9,23,1,23,3,23,524,8,23,1,23,1,23,1,23,3,23,
        529,8,23,1,23,1,23,1,23,1,23,1,23,1,23,3,23,537,8,23,1,23,1,23,3,
        23,541,8,23,1,23,1,23,1,23,1,23,1,23,3,23,548,8,23,1,23,1,23,3,23,
        552,8,23,1,23,1,23,3,23,556,8,23,1,23,3,23,559,8,23,1,23,3,23,562,
        8,23,1,23,1,23,1,23,1,23,1,23,3,23,569,8,23,1,23,1,23,3,23,573,8,
        23,1,23,1,23,3,23,577,8,23,1,23,1,23,3,23,581,8,23,1,23,1,23,5,23,
        585,8,23,10,23,12,23,588,9,23,1,24,1,24,1,24,1,24,1,24,1,24,1,24,
        1,24,1,24,1,24,1,24,3,24,601,8,24,1,25,1,25,1,26,1,26,1,26,3,26,
        608,8,26,1,27,1,27,1,27,1,27,1,27,1,28,1,28,1,28,1,28,1,28,1,29,
        1,29,1,29,1,29,1,29,1,30,1,30,1,30,0,2,6,46,31,0,2,4,6,8,10,12,14,
        16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,
        60,0,5,2,0,13,13,72,72,1,0,24,26,1,0,19,20,1,0,1,16,2,0,18,18,38,
        76,751,0,76,1,0,0,0,2,93,1,0,0,0,4,117,1,0,0,0,6,197,1,0,0,0,8,211,
        1,0,0,0,10,222,1,0,0,0,12,232,1,0,0,0,14,277,1,0,0,0,16,279,1,0,
        0,0,18,286,1,0,0,0,20,303,1,0,0,0,22,320,1,0,0,0,24,322,1,0,0,0,
        26,324,1,0,0,0,28,338,1,0,0,0,30,359,1,0,0,0,32,361,1,0,0,0,34,384,
        1,0,0,0,36,397,1,0,0,0,38,427,1,0,0,0,40,430,1,0,0,0,42,439,1,0,
        0,0,44,450,1,0,0,0,46,528,1,0,0,0,48,600,1,0,0,0,50,602,1,0,0,0,
        52,607,1,0,0,0,54,609,1,0,0,0,56,614,1,0,0,0,58,619,1,0,0,0,60,624,
        1,0,0,0,62,65,7,0,0,0,63,64,5,18,0,0,64,66,3,42,21,0,65,63,1,0,0,
        0,65,66,1,0,0,0,66,67,1,0,0,0,67,77,5,17,0,0,68,72,5,17,0,0,69,72,
        3,2,1,0,70,72,3,18,9,0,71,68,1,0,0,0,71,69,1,0,0,0,71,70,1,0,0,0,
        72,75,1,0,0,0,73,71,1,0,0,0,73,74,1,0,0,0,74,77,1,0,0,0,75,73,1,
        0,0,0,76,62,1,0,0,0,76,73,1,0,0,0,77,78,1,0,0,0,78,79,5,0,0,1,79,
        1,1,0,0,0,80,94,3,14,7,0,81,82,3,8,4,0,82,83,5,17,0,0,83,94,1,0,
        0,0,84,85,3,4,2,0,85,86,5,17,0,0,86,94,1,0,0,0,87,88,3,10,5,0,88,
        89,5,17,0,0,89,94,1,0,0,0,90,91,3,12,6,0,91,92,5,17,0,0,92,94,1,
        0,0,0,93,80,1,0,0,0,93,81,1,0,0,0,93,84,1,0,0,0,93,87,1,0,0,0,93,
        90,1,0,0,0,94,3,1,0,0,0,95,96,3,42,21,0,96,97,5,47,0,0,97,99,1,0,
        0,0,98,95,1,0,0,0,98,99,1,0,0,0,99,101,1,0,0,0,100,102,5,58,0,0,
        101,100,1,0,0,0,101,102,1,0,0,0,102,103,1,0,0,0,103,113,3,42,21,
        0,104,108,5,18,0,0,105,106,3,42,21,0,106,107,5,63,0,0,107,109,1,
        0,0,0,108,105,1,0,0,0,108,109,1,0,0,0,109,110,1,0,0,0,110,112,3,
        6,3,0,111,104,1,0,0,0,112,115,1,0,0,0,113,111,1,0,0,0,113,114,1,
        0,0,0,114,118,1,0,0,0,115,113,1,0,0,0,116,118,3,6,3,0,117,98,1,0,
        0,0,117,116,1,0,0,0,118,5,1,0,0,0,119,120,6,3,-1,0,120,122,5,2,0,
        0,121,123,5,18,0,0,122,121,1,0,0,0,122,123,1,0,0,0,123,124,1,0,0,
        0,124,126,3,28,14,0,125,127,5,18,0,0,126,125,1,0,0,0,126,127,1,0,
        0,0,127,128,1,0,0,0,128,130,5,3,0,0,129,131,5,18,0,0,130,129,1,0,
        0,0,130,131,1,0,0,0,131,132,1,0,0,0,132,134,3,6,3,0,133,135,5,18,
        0,0,134,133,1,0,0,0,134,135,1,0,0,0,135,136,1,0,0,0,136,138,5,4,
        0,0,137,139,5,18,0,0,138,137,1,0,0,0,138,139,1,0,0,0,139,140,1,0,
        0,0,140,141,3,6,3,9,141,198,1,0,0,0,142,144,5,36,0,0,143,145,5,18,
        0,0,144,143,1,0,0,0,144,145,1,0,0,0,145,146,1,0,0,0,146,148,3,4,
        2,0,147,149,5,18,0,0,148,147,1,0,0,0,148,149,1,0,0,0,149,150,1,0,
        0,0,150,151,5,37,0,0,151,198,1,0,0,0,152,153,5,5,0,0,153,155,5,36,
        0,0,154,156,5,18,0,0,155,154,1,0,0,0,155,156,1,0,0,0,156,157,1,0,
        0,0,157,159,3,6,3,0,158,160,5,18,0,0,159,158,1,0,0,0,159,160,1,0,
        0,0,160,179,1,0,0,0,161,163,5,43,0,0,162,164,5,18,0,0,163,162,1,
        0,0,0,163,164,1,0,0,0,164,165,1,0,0,0,165,167,3,6,3,0,166,168,5,
        18,0,0,167,166,1,0,0,0,167,168,1,0,0,0,168,177,1,0,0,0,169,171,5,
        43,0,0,170,172,5,18,0,0,171,170,1,0,0,0,171,172,1,0,0,0,172,173,
        1,0,0,0,173,175,3,6,3,0,174,176,5,18,0,0,175,174,1,0,0,0,175,176,
        1,0,0,0,176,178,1,0,0,0,177,169,1,0,0,0,177,178,1,0,0,0,178,180,
        1,0,0,0,179,161,1,0,0,0,179,180,1,0,0,0,180,181,1,0,0,0,181,182,
        5,37,0,0,182,198,1,0,0,0,183,198,3,52,26,0,184,198,3,38,19,0,185,
        198,5,12,0,0,186,188,3,46,23,0,187,189,5,18,0,0,188,187,1,0,0,0,
        188,189,1,0,0,0,189,190,1,0,0,0,190,192,3,30,15,0,191,193,5,18,0,
        0,192,191,1,0,0,0,192,193,1,0,0,0,193,194,1,0,0,0,194,195,3,6,3,
        0,195,198,1,0,0,0,196,198,3,46,23,0,197,119,1,0,0,0,197,142,1,0,
        0,0,197,152,1,0,0,0,197,183,1,0,0,0,197,184,1,0,0,0,197,185,1,0,
        0,0,197,186,1,0,0,0,197,196,1,0,0,0,198,206,1,0,0,0,199,200,10,6,
        0,0,200,201,5,18,0,0,201,202,5,10,0,0,202,203,5,18,0,0,203,205,3,
        6,3,7,204,199,1,0,0,0,205,208,1,0,0,0,206,204,1,0,0,0,206,207,1,
        0,0,0,207,7,1,0,0,0,208,206,1,0,0,0,209,212,3,10,5,0,210,212,3,46,
        23,0,211,209,1,0,0,0,211,210,1,0,0,0,212,214,1,0,0,0,213,215,5,18,
        0,0,214,213,1,0,0,0,214,215,1,0,0,0,215,216,1,0,0,0,216,218,5,63,
        0,0,217,219,5,18,0,0,218,217,1,0,0,0,218,219,1,0,0,0,219,220,1,0,
        0,0,220,221,3,4,2,0,221,9,1,0,0,0,222,223,5,1,0,0,223,224,5,18,0,
        0,224,225,3,42,21,0,225,11,1,0,0,0,226,227,5,38,0,0,227,233,3,32,
        16,0,228,229,5,39,0,0,229,233,3,4,2,0,230,231,5,40,0,0,231,233,3,
        36,18,0,232,226,1,0,0,0,232,228,1,0,0,0,232,230,1,0,0,0,233,13,1,
        0,0,0,234,235,5,7,0,0,235,236,5,18,0,0,236,238,3,28,14,0,237,239,
        5,18,0,0,238,237,1,0,0,0,238,239,1,0,0,0,239,240,1,0,0,0,240,241,
        5,41,0,0,241,243,3,20,10,0,242,244,3,16,8,0,243,242,1,0,0,0,243,
        244,1,0,0,0,244,278,1,0,0,0,245,246,5,9,0,0,246,247,5,18,0,0,247,
        256,3,42,21,0,248,250,5,18,0,0,249,248,1,0,0,0,249,250,1,0,0,0,250,
        251,1,0,0,0,251,253,5,43,0,0,252,254,5,18,0,0,253,252,1,0,0,0,253,
        254,1,0,0,0,254,255,1,0,0,0,255,257,3,42,21,0,256,249,1,0,0,0,256,
        257,1,0,0,0,257,258,1,0,0,0,258,259,5,18,0,0,259,260,5,10,0,0,260,
        261,5,18,0,0,261,263,3,24,12,0,262,264,5,18,0,0,263,262,1,0,0,0,
        263,264,1,0,0,0,264,265,1,0,0,0,265,266,5,41,0,0,266,267,3,20,10,
        0,267,278,1,0,0,0,268,269,5,11,0,0,269,270,5,18,0,0,270,272,3,28,
        14,0,271,273,5,18,0,0,272,271,1,0,0,0,272,273,1,0,0,0,273,274,1,
        0,0,0,274,275,5,41,0,0,275,276,3,20,10,0,276,278,1,0,0,0,277,234,
        1,0,0,0,277,245,1,0,0,0,277,268,1,0,0,0,278,15,1,0,0,0,279,281,5,
        8,0,0,280,282,5,18,0,0,281,280,1,0,0,0,281,282,1,0,0,0,282,283,1,
        0,0,0,283,284,5,41,0,0,284,285,3,20,10,0,285,17,1,0,0,0,286,287,
        5,6,0,0,287,288,5,18,0,0,288,290,3,42,21,0,289,291,5,18,0,0,290,
        289,1,0,0,0,290,291,1,0,0,0,291,292,1,0,0,0,292,294,5,36,0,0,293,
        295,3,26,13,0,294,293,1,0,0,0,294,295,1,0,0,0,295,296,1,0,0,0,296,
        298,5,37,0,0,297,299,5,18,0,0,298,297,1,0,0,0,298,299,1,0,0,0,299,
        300,1,0,0,0,300,301,5,41,0,0,301,302,3,20,10,0,302,19,1,0,0,0,303,
        308,5,78,0,0,304,306,3,22,11,0,305,307,5,17,0,0,306,305,1,0,0,0,
        306,307,1,0,0,0,307,309,1,0,0,0,308,304,1,0,0,0,309,310,1,0,0,0,
        310,308,1,0,0,0,310,311,1,0,0,0,311,312,1,0,0,0,312,313,5,79,0,0,
        313,21,1,0,0,0,314,321,5,15,0,0,315,321,5,16,0,0,316,317,5,14,0,
        0,317,318,5,18,0,0,318,321,3,4,2,0,319,321,3,2,1,0,320,314,1,0,0,
        0,320,315,1,0,0,0,320,316,1,0,0,0,320,319,1,0,0,0,321,23,1,0,0,0,
        322,323,3,4,2,0,323,25,1,0,0,0,324,335,3,42,21,0,325,327,5,18,0,
        0,326,325,1,0,0,0,326,327,1,0,0,0,327,328,1,0,0,0,328,330,5,43,0,
        0,329,331,5,18,0,0,330,329,1,0,0,0,330,331,1,0,0,0,331,332,1,0,0,
        0,332,334,3,42,21,0,333,326,1,0,0,0,334,337,1,0,0,0,335,333,1,0,
        0,0,335,336,1,0,0,0,336,27,1,0,0,0,337,335,1,0,0,0,338,339,3,4,2,
        0,339,29,1,0,0,0,340,360,5,57,0,0,341,360,5,76,0,0,342,360,5,56,
        0,0,343,360,5,58,0,0,344,360,5,55,0,0,345,360,5,62,0,0,346,360,5,
        64,0,0,347,360,5,65,0,0,348,360,5,67,0,0,349,360,5,66,0,0,350,360,
        5,68,0,0,351,360,5,69,0,0,352,360,5,70,0,0,353,354,5,71,0,0,354,
        360,5,59,0,0,355,360,5,60,0,0,356,360,5,61,0,0,357,360,5,39,0,0,
        358,360,5,48,0,0,359,340,1,0,0,0,359,341,1,0,0,0,359,342,1,0,0,0,
        359,343,1,0,0,0,359,344,1,0,0,0,359,345,1,0,0,0,359,346,1,0,0,0,
        359,347,1,0,0,0,359,348,1,0,0,0,359,349,1,0,0,0,359,350,1,0,0,0,
        359,351,1,0,0,0,359,352,1,0,0,0,359,353,1,0,0,0,359,355,1,0,0,0,
        359,356,1,0,0,0,359,357,1,0,0,0,359,358,1,0,0,0,360,31,1,0,0,0,361,
        363,3,42,21,0,362,364,5,18,0,0,363,362,1,0,0,0,363,364,1,0,0,0,364,
        365,1,0,0,0,365,367,5,36,0,0,366,368,5,18,0,0,367,366,1,0,0,0,367,
        368,1,0,0,0,368,372,1,0,0,0,369,371,3,34,17,0,370,369,1,0,0,0,371,
        374,1,0,0,0,372,370,1,0,0,0,372,373,1,0,0,0,373,375,1,0,0,0,374,
        372,1,0,0,0,375,376,5,37,0,0,376,33,1,0,0,0,377,385,3,38,19,0,378,
        385,3,52,26,0,379,385,3,48,24,0,380,381,5,36,0,0,381,382,3,34,17,
        0,382,383,5,37,0,0,383,385,1,0,0,0,384,377,1,0,0,0,384,378,1,0,0,
        0,384,379,1,0,0,0,384,380,1,0,0,0,385,386,1,0,0,0,386,384,1,0,0,
        0,386,387,1,0,0,0,387,35,1,0,0,0,388,396,3,38,19,0,389,396,3,52,
        26,0,390,396,3,48,24,0,391,392,5,36,0,0,392,393,3,36,18,0,393,394,
        5,37,0,0,394,396,1,0,0,0,395,388,1,0,0,0,395,389,1,0,0,0,395,390,
        1,0,0,0,395,391,1,0,0,0,396,399,1,0,0,0,397,395,1,0,0,0,397,398,
        1,0,0,0,398,37,1,0,0,0,399,397,1,0,0,0,400,401,7,1,0,0,401,402,5,
        47,0,0,402,404,3,42,21,0,403,405,5,38,0,0,404,403,1,0,0,0,404,405,
        1,0,0,0,405,428,1,0,0,0,406,428,5,28,0,0,407,408,5,27,0,0,408,410,
        5,49,0,0,409,411,5,18,0,0,410,409,1,0,0,0,410,411,1,0,0,0,411,412,
        1,0,0,0,412,421,3,40,20,0,413,415,5,18,0,0,414,413,1,0,0,0,414,415,
        1,0,0,0,415,416,1,0,0,0,416,418,5,35,0,0,417,419,5,18,0,0,418,417,
        1,0,0,0,418,419,1,0,0,0,419,420,1,0,0,0,420,422,3,40,20,0,421,414,
        1,0,0,0,421,422,1,0,0,0,422,423,1,0,0,0,423,425,5,50,0,0,424,426,
        5,38,0,0,425,424,1,0,0,0,425,426,1,0,0,0,426,428,1,0,0,0,427,400,
        1,0,0,0,427,406,1,0,0,0,427,407,1,0,0,0,428,39,1,0,0,0,429,431,5,
        76,0,0,430,429,1,0,0,0,430,431,1,0,0,0,431,432,1,0,0,0,432,433,3,
        4,2,0,433,41,1,0,0,0,434,440,5,22,0,0,435,440,5,75,0,0,436,437,3,
        50,25,0,437,438,5,75,0,0,438,440,1,0,0,0,439,434,1,0,0,0,439,435,
        1,0,0,0,439,436,1,0,0,0,440,447,1,0,0,0,441,446,5,22,0,0,442,446,
        5,20,0,0,443,446,5,75,0,0,444,446,3,50,25,0,445,441,1,0,0,0,445,
        442,1,0,0,0,445,443,1,0,0,0,445,444,1,0,0,0,446,449,1,0,0,0,447,
        445,1,0,0,0,447,448,1,0,0,0,448,43,1,0,0,0,449,447,1,0,0,0,450,451,
        7,2,0,0,451,45,1,0,0,0,452,453,6,23,-1,0,453,455,3,42,21,0,454,456,
        5,38,0,0,455,454,1,0,0,0,455,456,1,0,0,0,456,529,1,0,0,0,457,459,
        5,76,0,0,458,457,1,0,0,0,458,459,1,0,0,0,459,460,1,0,0,0,460,529,
        3,44,22,0,461,529,5,12,0,0,462,529,3,38,19,0,463,465,5,49,0,0,464,
        466,5,18,0,0,465,464,1,0,0,0,465,466,1,0,0,0,466,468,1,0,0,0,467,
        469,3,46,23,0,468,467,1,0,0,0,468,469,1,0,0,0,469,480,1,0,0,0,470,
        472,5,18,0,0,471,470,1,0,0,0,471,472,1,0,0,0,472,473,1,0,0,0,473,
        475,5,43,0,0,474,476,5,18,0,0,475,474,1,0,0,0,475,476,1,0,0,0,476,
        477,1,0,0,0,477,479,3,46,23,0,478,471,1,0,0,0,479,482,1,0,0,0,480,
        478,1,0,0,0,480,481,1,0,0,0,481,484,1,0,0,0,482,480,1,0,0,0,483,
        485,5,18,0,0,484,483,1,0,0,0,484,485,1,0,0,0,485,486,1,0,0,0,486,
        529,5,50,0,0,487,489,5,51,0,0,488,490,5,18,0,0,489,488,1,0,0,0,489,
        490,1,0,0,0,490,519,1,0,0,0,491,493,5,29,0,0,492,494,5,18,0,0,493,
        492,1,0,0,0,493,494,1,0,0,0,494,495,1,0,0,0,495,497,5,41,0,0,496,
        498,5,18,0,0,497,496,1,0,0,0,497,498,1,0,0,0,498,499,1,0,0,0,499,
        501,3,46,23,0,500,502,5,18,0,0,501,500,1,0,0,0,501,502,1,0,0,0,502,
        503,1,0,0,0,503,505,5,43,0,0,504,506,5,18,0,0,505,504,1,0,0,0,505,
        506,1,0,0,0,506,507,1,0,0,0,507,509,5,29,0,0,508,510,5,18,0,0,509,
        508,1,0,0,0,509,510,1,0,0,0,510,511,1,0,0,0,511,513,5,41,0,0,512,
        514,5,18,0,0,513,512,1,0,0,0,513,514,1,0,0,0,514,515,1,0,0,0,515,
        516,3,46,23,0,516,518,1,0,0,0,517,491,1,0,0,0,518,521,1,0,0,0,519,
        517,1,0,0,0,519,520,1,0,0,0,520,523,1,0,0,0,521,519,1,0,0,0,522,
        524,5,18,0,0,523,522,1,0,0,0,523,524,1,0,0,0,524,525,1,0,0,0,525,
        529,5,52,0,0,526,529,5,29,0,0,527,529,5,30,0,0,528,452,1,0,0,0,528,
        458,1,0,0,0,528,461,1,0,0,0,528,462,1,0,0,0,528,463,1,0,0,0,528,
        487,1,0,0,0,528,526,1,0,0,0,528,527,1,0,0,0,529,586,1,0,0,0,530,
        531,10,8,0,0,531,532,5,47,0,0,532,585,3,42,21,0,533,534,10,7,0,0,
        534,536,5,49,0,0,535,537,5,18,0,0,536,535,1,0,0,0,536,537,1,0,0,
        0,537,538,1,0,0,0,538,540,3,40,20,0,539,541,5,18,0,0,540,539,1,0,
        0,0,540,541,1,0,0,0,541,542,1,0,0,0,542,543,5,50,0,0,543,585,1,0,
        0,0,544,545,10,6,0,0,545,547,5,49,0,0,546,548,5,18,0,0,547,546,1,
        0,0,0,547,548,1,0,0,0,548,549,1,0,0,0,549,551,3,40,20,0,550,552,
        5,18,0,0,551,550,1,0,0,0,551,552,1,0,0,0,552,553,1,0,0,0,553,555,
        5,41,0,0,554,556,5,18,0,0,555,554,1,0,0,0,555,556,1,0,0,0,556,558,
        1,0,0,0,557,559,3,40,20,0,558,557,1,0,0,0,558,559,1,0,0,0,559,561,
        1,0,0,0,560,562,5,18,0,0,561,560,1,0,0,0,561,562,1,0,0,0,562,563,
        1,0,0,0,563,564,5,50,0,0,564,585,1,0,0,0,565,566,10,5,0,0,566,568,
        5,49,0,0,567,569,5,18,0,0,568,567,1,0,0,0,568,569,1,0,0,0,569,570,
        1,0,0,0,570,572,3,40,20,0,571,573,5,18,0,0,572,571,1,0,0,0,572,573,
        1,0,0,0,573,574,1,0,0,0,574,576,5,35,0,0,575,577,5,18,0,0,576,575,
        1,0,0,0,576,577,1,0,0,0,577,578,1,0,0,0,578,580,3,40,20,0,579,581,
        5,18,0,0,580,579,1,0,0,0,580,581,1,0,0,0,581,582,1,0,0,0,582,583,
        5,50,0,0,583,585,1,0,0,0,584,530,1,0,0,0,584,533,1,0,0,0,584,544,
        1,0,0,0,584,565,1,0,0,0,585,588,1,0,0,0,586,584,1,0,0,0,586,587,
        1,0,0,0,587,47,1,0,0,0,588,586,1,0,0,0,589,601,5,22,0,0,590,601,
        5,20,0,0,591,601,3,60,30,0,592,601,5,29,0,0,593,601,5,30,0,0,594,
        601,5,18,0,0,595,596,5,36,0,0,596,597,3,48,24,0,597,598,5,37,0,0,
        598,601,1,0,0,0,599,601,3,50,25,0,600,589,1,0,0,0,600,590,1,0,0,
        0,600,591,1,0,0,0,600,592,1,0,0,0,600,593,1,0,0,0,600,594,1,0,0,
        0,600,595,1,0,0,0,600,599,1,0,0,0,601,49,1,0,0,0,602,603,7,3,0,0,
        603,51,1,0,0,0,604,608,3,54,27,0,605,608,3,56,28,0,606,608,3,58,
        29,0,607,604,1,0,0,0,607,605,1,0,0,0,607,606,1,0,0,0,608,53,1,0,
        0,0,609,610,5,39,0,0,610,611,5,36,0,0,611,612,3,4,2,0,612,613,5,
        37,0,0,613,55,1,0,0,0,614,615,5,40,0,0,615,616,5,36,0,0,616,617,
        3,36,18,0,617,618,5,37,0,0,618,57,1,0,0,0,619,620,5,38,0,0,620,621,
        5,36,0,0,621,622,3,34,17,0,622,623,5,37,0,0,623,59,1,0,0,0,624,625,
        7,4,0,0,625,61,1,0,0,0,103,65,71,73,76,93,98,101,108,113,117,122,
        126,130,134,138,144,148,155,159,163,167,171,175,177,179,188,192,
        197,206,211,214,218,232,238,243,249,253,256,263,272,277,281,290,
        294,298,306,310,320,326,330,335,359,363,367,372,384,386,395,397,
        404,410,414,418,421,425,427,430,439,445,447,455,458,465,468,471,
        475,480,484,489,493,497,501,505,509,513,519,523,528,536,540,547,
        551,555,558,561,568,572,576,580,584,586,600,607
    ]

class dAngrParser ( Parser ):

    grammarFileName = "dAngr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'static'", "'IIF'", "'THEN'", "'ELSE'", 
                     "'range'", "'def'", "'if'", "'else'", "'for'", "'in'", 
                     "'while'", "<INVALID>", "'help'", "'return'", "'break'", 
                     "'continue'", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "'&sym'", "'&reg'", "'&vars'", "'&mem'", "'&state'", 
                     "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "<INVALID>", "'->'", "'('", "')'", "'!'", 
                     "'&'", "'$'", "':'", "';'", "','", "'\"'", "'''", "'@'", 
                     "'.'", "'|'", "'['", "']'", "'{'", "'}'", "'^'", "'#'", 
                     "'%'", "'*'", "'+'", "'/'", "'//'", "'<<'", "'>>'", 
                     "'**'", "'='", "'=='", "'!='", "'<'", "'>'", "'<='", 
                     "'>='", "'&&'", "'||'", "'?'", "'~'", "'`'", "'_'", 
                     "'-'", "'\\'" ]

    symbolicNames = [ "<INVALID>", "STATIC", "CIF", "CTHEN", "CELSE", "RANGE", 
                      "DEF", "IF", "ELSE", "FOR", "IN", "WHILE", "BOOL", 
                      "HELP", "RETURN", "BREAK", "CONTINUE", "NEWLINE", 
                      "WS", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", 
                      "LETTER", "SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", 
                      "STATE", "STRING", "BINARY_STRING", "ESCAPED_QUOTE", 
                      "ESCAPED_SINGLE_QUOTE", "SESC_SEQ", "ESC_SEQ", "ARROW", 
                      "LPAREN", "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", 
                      "SCOLON", "COMMA", "QUOTE", "SQUOTE", "AT", "DOT", 
                      "BAR", "BRA", "KET", "BRACE", "KETCE", "HAT", "HASH", 
                      "PERC", "MUL", "ADD", "DIV", "FLOORDIV", "LSHIFT", 
                      "RSHIFT", "POW", "ASSIGN", "EQ", "NEQ", "LT", "GT", 
                      "LE", "GE", "AND", "OR", "QMARK", "TILDE", "TICK", 
                      "UNDERSCORE", "DASH", "BACKSLASH", "INDENT", "DEDENT" ]

    RULE_script = 0
    RULE_statement = 1
    RULE_expression = 2
    RULE_expression_part = 3
    RULE_assignment = 4
    RULE_static_var = 5
    RULE_ext_command = 6
    RULE_control_flow = 7
    RULE_else_ = 8
    RULE_function_def = 9
    RULE_body = 10
    RULE_fstatement = 11
    RULE_iterable = 12
    RULE_parameters = 13
    RULE_condition = 14
    RULE_operation = 15
    RULE_py_basic_content = 16
    RULE_py_content = 17
    RULE_bash_content = 18
    RULE_reference = 19
    RULE_index = 20
    RULE_identifier = 21
    RULE_numeric = 22
    RULE_object = 23
    RULE_anything = 24
    RULE_special_words = 25
    RULE_range = 26
    RULE_dangr_range = 27
    RULE_bash_range = 28
    RULE_python_range = 29
    RULE_symbol = 30

    ruleNames =  [ "script", "statement", "expression", "expression_part", 
                   "assignment", "static_var", "ext_command", "control_flow", 
                   "else_", "function_def", "body", "fstatement", "iterable", 
                   "parameters", "condition", "operation", "py_basic_content", 
                   "py_content", "bash_content", "reference", "index", "identifier", 
                   "numeric", "object", "anything", "special_words", "range", 
                   "dangr_range", "bash_range", "python_range", "symbol" ]

    EOF = Token.EOF
    STATIC=1
    CIF=2
    CTHEN=3
    CELSE=4
    RANGE=5
    DEF=6
    IF=7
    ELSE=8
    FOR=9
    IN=10
    WHILE=11
    BOOL=12
    HELP=13
    RETURN=14
    BREAK=15
    CONTINUE=16
    NEWLINE=17
    WS=18
    HEX_NUMBERS=19
    NUMBERS=20
    NUMBER=21
    LETTERS=22
    LETTER=23
    SYM_DB=24
    REG_DB=25
    VARS_DB=26
    MEM_DB=27
    STATE=28
    STRING=29
    BINARY_STRING=30
    ESCAPED_QUOTE=31
    ESCAPED_SINGLE_QUOTE=32
    SESC_SEQ=33
    ESC_SEQ=34
    ARROW=35
    LPAREN=36
    RPAREN=37
    BANG=38
    AMP=39
    DOLLAR=40
    COLON=41
    SCOLON=42
    COMMA=43
    QUOTE=44
    SQUOTE=45
    AT=46
    DOT=47
    BAR=48
    BRA=49
    KET=50
    BRACE=51
    KETCE=52
    HAT=53
    HASH=54
    PERC=55
    MUL=56
    ADD=57
    DIV=58
    FLOORDIV=59
    LSHIFT=60
    RSHIFT=61
    POW=62
    ASSIGN=63
    EQ=64
    NEQ=65
    LT=66
    GT=67
    LE=68
    GE=69
    AND=70
    OR=71
    QMARK=72
    TILDE=73
    TICK=74
    UNDERSCORE=75
    DASH=76
    BACKSLASH=77
    INDENT=78
    DEDENT=79

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
                if not(_la==13 or _la==72):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 65
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
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
                while (((_la) & ~0x3f) == 0 and ((1 << _la) & 291047120920379390) != 0) or _la==75 or _la==76:
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


        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

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
            self.state = 117
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,9,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 98
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
                if la_ == 1:
                    self.state = 95
                    self.identifier()
                    self.state = 96
                    self.match(dAngrParser.DOT)


                self.state = 101
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==58:
                    self.state = 100
                    self.match(dAngrParser.DIV)


                self.state = 103
                self.identifier()
                self.state = 113
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,8,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 104
                        self.match(dAngrParser.WS)
                        self.state = 108
                        self._errHandler.sync(self)
                        la_ = self._interp.adaptivePredict(self._input,7,self._ctx)
                        if la_ == 1:
                            self.state = 105
                            self.identifier()
                            self.state = 106
                            self.match(dAngrParser.ASSIGN)


                        self.state = 110
                        self.expression_part(0) 
                    self.state = 115
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,8,self._ctx)

                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 116
                self.expression_part(0)
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


        def getRuleIndex(self):
            return dAngrParser.RULE_expression_part

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class ExpressionRangeContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def RANGE(self):
            return self.getToken(dAngrParser.RANGE, 0)
        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)
        def expression_part(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Expression_partContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Expression_partContext,i)

        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)
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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionRange" ):
                listener.enterExpressionRange(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionRange" ):
                listener.exitExpressionRange(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionRange" ):
                return visitor.visitExpressionRange(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionInContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def expression_part(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Expression_partContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Expression_partContext,i)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)
        def IN(self):
            return self.getToken(dAngrParser.IN, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionIn" ):
                listener.enterExpressionIn(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionIn" ):
                listener.exitExpressionIn(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionIn" ):
                return visitor.visitExpressionIn(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionObjectContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionObject" ):
                listener.enterExpressionObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionObject" ):
                listener.exitExpressionObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionObject" ):
                return visitor.visitExpressionObject(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionBoolContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionBool" ):
                listener.enterExpressionBool(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionBool" ):
                listener.exitExpressionBool(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionBool" ):
                return visitor.visitExpressionBool(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionReferenceContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def reference(self):
            return self.getTypedRuleContext(dAngrParser.ReferenceContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionReference" ):
                listener.enterExpressionReference(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionReference" ):
                listener.exitExpressionReference(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionReference" ):
                return visitor.visitExpressionReference(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionIfContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionIf" ):
                listener.enterExpressionIf(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionIf" ):
                listener.exitExpressionIf(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionIf" ):
                return visitor.visitExpressionIf(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionAltContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def range_(self):
            return self.getTypedRuleContext(dAngrParser.RangeContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionAlt" ):
                listener.enterExpressionAlt(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionAlt" ):
                listener.exitExpressionAlt(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionAlt" ):
                return visitor.visitExpressionAlt(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionParenthesisContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionParenthesis" ):
                listener.enterExpressionParenthesis(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionParenthesis" ):
                listener.exitExpressionParenthesis(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionParenthesis" ):
                return visitor.visitExpressionParenthesis(self)
            else:
                return visitor.visitChildren(self)


    class ExpressionOperationContext(Expression_partContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.Expression_partContext
            super().__init__(parser)
            self.copyFrom(ctx)

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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterExpressionOperation" ):
                listener.enterExpressionOperation(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitExpressionOperation" ):
                listener.exitExpressionOperation(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitExpressionOperation" ):
                return visitor.visitExpressionOperation(self)
            else:
                return visitor.visitChildren(self)



    def expression_part(self, _p:int=0):
        _parentctx = self._ctx
        _parentState = self.state
        localctx = dAngrParser.Expression_partContext(self, self._ctx, _parentState)
        _prevctx = localctx
        _startState = 6
        self.enterRecursionRule(localctx, 6, self.RULE_expression_part, _p)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 197
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,27,self._ctx)
            if la_ == 1:
                localctx = dAngrParser.ExpressionIfContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 120
                self.match(dAngrParser.CIF)
                self.state = 122
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 121
                    self.match(dAngrParser.WS)


                self.state = 124
                self.condition()
                self.state = 126
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 125
                    self.match(dAngrParser.WS)


                self.state = 128
                self.match(dAngrParser.CTHEN)
                self.state = 130
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 129
                    self.match(dAngrParser.WS)


                self.state = 132
                self.expression_part(0)
                self.state = 134
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 133
                    self.match(dAngrParser.WS)


                self.state = 136
                self.match(dAngrParser.CELSE)
                self.state = 138
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 137
                    self.match(dAngrParser.WS)


                self.state = 140
                self.expression_part(9)
                pass

            elif la_ == 2:
                localctx = dAngrParser.ExpressionParenthesisContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 142
                self.match(dAngrParser.LPAREN)
                self.state = 144
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 143
                    self.match(dAngrParser.WS)


                self.state = 146
                self.expression()
                self.state = 148
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 147
                    self.match(dAngrParser.WS)


                self.state = 150
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 3:
                localctx = dAngrParser.ExpressionRangeContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 152
                self.match(dAngrParser.RANGE)
                self.state = 153
                self.match(dAngrParser.LPAREN)
                self.state = 155
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 154
                    self.match(dAngrParser.WS)


                self.state = 157
                self.expression_part(0)
                self.state = 159
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 158
                    self.match(dAngrParser.WS)


                self.state = 179
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==43:
                    self.state = 161
                    self.match(dAngrParser.COMMA)
                    self.state = 163
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 162
                        self.match(dAngrParser.WS)


                    self.state = 165
                    self.expression_part(0)
                    self.state = 167
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 166
                        self.match(dAngrParser.WS)


                    self.state = 177
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==43:
                        self.state = 169
                        self.match(dAngrParser.COMMA)
                        self.state = 171
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 170
                            self.match(dAngrParser.WS)


                        self.state = 173
                        self.expression_part(0)
                        self.state = 175
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 174
                            self.match(dAngrParser.WS)






                self.state = 181
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 4:
                localctx = dAngrParser.ExpressionAltContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 183
                self.range_()
                pass

            elif la_ == 5:
                localctx = dAngrParser.ExpressionReferenceContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 184
                self.reference()
                pass

            elif la_ == 6:
                localctx = dAngrParser.ExpressionBoolContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 185
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 7:
                localctx = dAngrParser.ExpressionOperationContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 186
                self.object_(0)

                self.state = 188
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 187
                    self.match(dAngrParser.WS)


                self.state = 190
                self.operation()
                self.state = 192
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 191
                    self.match(dAngrParser.WS)


                self.state = 194
                self.expression_part(0)
                pass

            elif la_ == 8:
                localctx = dAngrParser.ExpressionObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 196
                self.object_(0)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 206
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,28,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    localctx = dAngrParser.ExpressionInContext(self, dAngrParser.Expression_partContext(self, _parentctx, _parentState))
                    self.pushNewRecursionContext(localctx, _startState, self.RULE_expression_part)
                    self.state = 199
                    if not self.precpred(self._ctx, 6):
                        from antlr4.error.Errors import FailedPredicateException
                        raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                    self.state = 200
                    self.match(dAngrParser.WS)
                    self.state = 201
                    self.match(dAngrParser.IN)
                    self.state = 202
                    self.match(dAngrParser.WS)
                    self.state = 203
                    self.expression_part(7) 
                self.state = 208
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,28,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
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
        self.enterRule(localctx, 8, self.RULE_assignment)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 211
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,29,self._ctx)
            if la_ == 1:
                self.state = 209
                self.static_var()
                pass

            elif la_ == 2:
                self.state = 210
                self.object_(0)
                pass


            self.state = 214
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 213
                self.match(dAngrParser.WS)


            self.state = 216
            self.match(dAngrParser.ASSIGN)
            self.state = 218
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 217
                self.match(dAngrParser.WS)


            self.state = 220
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
        self.enterRule(localctx, 10, self.RULE_static_var)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 222
            self.match(dAngrParser.STATIC)
            self.state = 223
            self.match(dAngrParser.WS)
            self.state = 224
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
        self.enterRule(localctx, 12, self.RULE_ext_command)
        try:
            self.state = 232
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [38]:
                self.enterOuterAlt(localctx, 1)
                self.state = 226
                self.match(dAngrParser.BANG)
                self.state = 227
                self.py_basic_content()
                pass
            elif token in [39]:
                self.enterOuterAlt(localctx, 2)
                self.state = 228
                self.match(dAngrParser.AMP)
                self.state = 229
                self.expression()
                pass
            elif token in [40]:
                self.enterOuterAlt(localctx, 3)
                self.state = 230
                self.match(dAngrParser.DOLLAR)
                self.state = 231
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
        self.enterRule(localctx, 14, self.RULE_control_flow)
        self._la = 0 # Token type
        try:
            self.state = 277
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [7]:
                self.enterOuterAlt(localctx, 1)
                self.state = 234
                self.match(dAngrParser.IF)
                self.state = 235
                self.match(dAngrParser.WS)
                self.state = 236
                self.condition()
                self.state = 238
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 237
                    self.match(dAngrParser.WS)


                self.state = 240
                self.match(dAngrParser.COLON)
                self.state = 241
                self.body()
                self.state = 243
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,34,self._ctx)
                if la_ == 1:
                    self.state = 242
                    self.else_()


                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 2)
                self.state = 245
                self.match(dAngrParser.FOR)
                self.state = 246
                self.match(dAngrParser.WS)
                self.state = 247
                self.identifier()
                self.state = 256
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,37,self._ctx)
                if la_ == 1:
                    self.state = 249
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 248
                        self.match(dAngrParser.WS)


                    self.state = 251
                    self.match(dAngrParser.COMMA)
                    self.state = 253
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 252
                        self.match(dAngrParser.WS)


                    self.state = 255
                    self.identifier()


                self.state = 258
                self.match(dAngrParser.WS)
                self.state = 259
                self.match(dAngrParser.IN)
                self.state = 260
                self.match(dAngrParser.WS)
                self.state = 261
                self.iterable()
                self.state = 263
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 262
                    self.match(dAngrParser.WS)


                self.state = 265
                self.match(dAngrParser.COLON)
                self.state = 266
                self.body()
                pass
            elif token in [11]:
                self.enterOuterAlt(localctx, 3)
                self.state = 268
                self.match(dAngrParser.WHILE)
                self.state = 269
                self.match(dAngrParser.WS)
                self.state = 270
                self.condition()
                self.state = 272
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 271
                    self.match(dAngrParser.WS)


                self.state = 274
                self.match(dAngrParser.COLON)
                self.state = 275
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
        self.enterRule(localctx, 16, self.RULE_else_)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 279
            self.match(dAngrParser.ELSE)
            self.state = 281
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 280
                self.match(dAngrParser.WS)


            self.state = 283
            self.match(dAngrParser.COLON)
            self.state = 284
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
        self.enterRule(localctx, 18, self.RULE_function_def)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 286
            self.match(dAngrParser.DEF)
            self.state = 287
            self.match(dAngrParser.WS)
            self.state = 288
            self.identifier()
            self.state = 290
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 289
                self.match(dAngrParser.WS)


            self.state = 292
            self.match(dAngrParser.LPAREN)
            self.state = 294
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if (((_la) & ~0x3f) == 0 and ((1 << _la) & 4325374) != 0) or _la==75:
                self.state = 293
                self.parameters()


            self.state = 296
            self.match(dAngrParser.RPAREN)
            self.state = 298
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 297
                self.match(dAngrParser.WS)


            self.state = 300
            self.match(dAngrParser.COLON)
            self.state = 301
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
        self.enterRule(localctx, 20, self.RULE_body)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 303
            self.match(dAngrParser.INDENT)
            self.state = 308 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 304
                self.fstatement()
                self.state = 306
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==17:
                    self.state = 305
                    self.match(dAngrParser.NEWLINE)


                self.state = 310 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 291047120920248318) != 0) or _la==75 or _la==76):
                    break

            self.state = 312
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

        def BREAK(self):
            return self.getToken(dAngrParser.BREAK, 0)

        def CONTINUE(self):
            return self.getToken(dAngrParser.CONTINUE, 0)

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
        self.enterRule(localctx, 22, self.RULE_fstatement)
        try:
            self.state = 320
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,47,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 314
                self.match(dAngrParser.BREAK)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 315
                self.match(dAngrParser.CONTINUE)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 316
                self.match(dAngrParser.RETURN)
                self.state = 317
                self.match(dAngrParser.WS)
                self.state = 318
                self.expression()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 319
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

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


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
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 322
            self.expression()
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
            self.state = 324
            self.identifier()
            self.state = 335
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==18 or _la==43:
                self.state = 326
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 325
                    self.match(dAngrParser.WS)


                self.state = 328
                self.match(dAngrParser.COMMA)
                self.state = 330
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 329
                    self.match(dAngrParser.WS)


                self.state = 332
                self.identifier()
                self.state = 337
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
            self.state = 338
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
        self.enterRule(localctx, 30, self.RULE_operation)
        try:
            self.state = 359
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [57]:
                self.enterOuterAlt(localctx, 1)
                self.state = 340
                self.match(dAngrParser.ADD)
                pass
            elif token in [76]:
                self.enterOuterAlt(localctx, 2)
                self.state = 341
                self.match(dAngrParser.DASH)
                pass
            elif token in [56]:
                self.enterOuterAlt(localctx, 3)
                self.state = 342
                self.match(dAngrParser.MUL)
                pass
            elif token in [58]:
                self.enterOuterAlt(localctx, 4)
                self.state = 343
                self.match(dAngrParser.DIV)
                pass
            elif token in [55]:
                self.enterOuterAlt(localctx, 5)
                self.state = 344
                self.match(dAngrParser.PERC)
                pass
            elif token in [62]:
                self.enterOuterAlt(localctx, 6)
                self.state = 345
                self.match(dAngrParser.POW)
                pass
            elif token in [64]:
                self.enterOuterAlt(localctx, 7)
                self.state = 346
                self.match(dAngrParser.EQ)
                pass
            elif token in [65]:
                self.enterOuterAlt(localctx, 8)
                self.state = 347
                self.match(dAngrParser.NEQ)
                pass
            elif token in [67]:
                self.enterOuterAlt(localctx, 9)
                self.state = 348
                self.match(dAngrParser.GT)
                pass
            elif token in [66]:
                self.enterOuterAlt(localctx, 10)
                self.state = 349
                self.match(dAngrParser.LT)
                pass
            elif token in [68]:
                self.enterOuterAlt(localctx, 11)
                self.state = 350
                self.match(dAngrParser.LE)
                pass
            elif token in [69]:
                self.enterOuterAlt(localctx, 12)
                self.state = 351
                self.match(dAngrParser.GE)
                pass
            elif token in [70]:
                self.enterOuterAlt(localctx, 13)
                self.state = 352
                self.match(dAngrParser.AND)
                pass
            elif token in [71]:
                self.enterOuterAlt(localctx, 14)
                self.state = 353
                self.match(dAngrParser.OR)
                self.state = 354
                self.match(dAngrParser.FLOORDIV)
                pass
            elif token in [60]:
                self.enterOuterAlt(localctx, 15)
                self.state = 355
                self.match(dAngrParser.LSHIFT)
                pass
            elif token in [61]:
                self.enterOuterAlt(localctx, 16)
                self.state = 356
                self.match(dAngrParser.RSHIFT)
                pass
            elif token in [39]:
                self.enterOuterAlt(localctx, 17)
                self.state = 357
                self.match(dAngrParser.AMP)
                pass
            elif token in [48]:
                self.enterOuterAlt(localctx, 18)
                self.state = 358
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
        self.enterRule(localctx, 32, self.RULE_py_basic_content)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 361
            self.identifier()
            self.state = 363
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 362
                self.match(dAngrParser.WS)


            self.state = 365
            self.match(dAngrParser.LPAREN)
            self.state = 367
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,53,self._ctx)
            if la_ == 1:
                self.state = 366
                self.match(dAngrParser.WS)


            self.state = 372
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & -204022087682) != 0) or ((((_la - 64)) & ~0x3f) == 0 and ((1 << (_la - 64)) & 8191) != 0):
                self.state = 369
                self.py_content()
                self.state = 374
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 375
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
            self.state = 384 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 384
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,55,self._ctx)
                    if la_ == 1:
                        self.state = 377
                        self.reference()
                        pass

                    elif la_ == 2:
                        self.state = 378
                        self.range_()
                        pass

                    elif la_ == 3:
                        self.state = 379
                        self.anything()
                        pass

                    elif la_ == 4:
                        self.state = 380
                        self.match(dAngrParser.LPAREN)
                        self.state = 381
                        self.py_content()
                        self.state = 382
                        self.match(dAngrParser.RPAREN)
                        pass



                else:
                    raise NoViableAltException(self)
                self.state = 386 
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,56,self._ctx)

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

        def bash_content(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.Bash_contentContext)
            else:
                return self.getTypedRuleContext(dAngrParser.Bash_contentContext,i)


        def RPAREN(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.RPAREN)
            else:
                return self.getToken(dAngrParser.RPAREN, i)

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
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 397
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while (((_la) & ~0x3f) == 0 and ((1 << _la) & -204022087682) != 0) or ((((_la - 64)) & ~0x3f) == 0 and ((1 << (_la - 64)) & 8191) != 0):
                self.state = 395
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,57,self._ctx)
                if la_ == 1:
                    self.state = 388
                    self.reference()
                    pass

                elif la_ == 2:
                    self.state = 389
                    self.range_()
                    pass

                elif la_ == 3:
                    self.state = 390
                    self.anything()
                    pass

                elif la_ == 4:
                    self.state = 391
                    self.match(dAngrParser.LPAREN)
                    self.state = 392
                    self.bash_content()
                    self.state = 393
                    self.match(dAngrParser.RPAREN)
                    pass


                self.state = 399
                self._errHandler.sync(self)
                _la = self._input.LA(1)

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

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

        def STATE(self):
            return self.getToken(dAngrParser.STATE, 0)

        def MEM_DB(self):
            return self.getToken(dAngrParser.MEM_DB, 0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)

        def index(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IndexContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IndexContext,i)


        def KET(self):
            return self.getToken(dAngrParser.KET, 0)

        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def ARROW(self):
            return self.getToken(dAngrParser.ARROW, 0)

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
            self.state = 427
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [24, 25, 26]:
                self.enterOuterAlt(localctx, 1)
                self.state = 400
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 117440512) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 401
                self.match(dAngrParser.DOT)
                self.state = 402
                self.identifier()
                self.state = 404
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,59,self._ctx)
                if la_ == 1:
                    self.state = 403
                    self.match(dAngrParser.BANG)


                pass
            elif token in [28]:
                self.enterOuterAlt(localctx, 2)
                self.state = 406
                self.match(dAngrParser.STATE)
                pass
            elif token in [27]:
                self.enterOuterAlt(localctx, 3)
                self.state = 407
                self.match(dAngrParser.MEM_DB)
                self.state = 408
                self.match(dAngrParser.BRA)
                self.state = 410
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 409
                    self.match(dAngrParser.WS)


                self.state = 412
                self.index()
                self.state = 421
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18 or _la==35:
                    self.state = 414
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 413
                        self.match(dAngrParser.WS)


                    self.state = 416
                    self.match(dAngrParser.ARROW)
                    self.state = 418
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 417
                        self.match(dAngrParser.WS)


                    self.state = 420
                    self.index()


                self.state = 423
                self.match(dAngrParser.KET)
                self.state = 425
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,64,self._ctx)
                if la_ == 1:
                    self.state = 424
                    self.match(dAngrParser.BANG)


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


    class IndexContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def expression(self):
            return self.getTypedRuleContext(dAngrParser.ExpressionContext,0)


        def DASH(self):
            return self.getToken(dAngrParser.DASH, 0)

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
            self.enterOuterAlt(localctx, 1)
            self.state = 430
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,66,self._ctx)
            if la_ == 1:
                self.state = 429
                self.match(dAngrParser.DASH)


            self.state = 432
            self.expression()
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
            self.state = 439
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [22]:
                self.state = 434
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [75]:
                self.state = 435
                self.match(dAngrParser.UNDERSCORE)
                pass
            elif token in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                self.state = 436
                self.special_words()
                self.state = 437
                self.match(dAngrParser.UNDERSCORE)
                pass
            else:
                raise NoViableAltException(self)

            self.state = 447
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,69,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 445
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [22]:
                        self.state = 441
                        self.match(dAngrParser.LETTERS)
                        pass
                    elif token in [20]:
                        self.state = 442
                        self.match(dAngrParser.NUMBERS)
                        pass
                    elif token in [75]:
                        self.state = 443
                        self.match(dAngrParser.UNDERSCORE)
                        pass
                    elif token in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                        self.state = 444
                        self.special_words()
                        pass
                    else:
                        raise NoViableAltException(self)
             
                self.state = 449
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,69,self._ctx)

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
            self.state = 450
            _la = self._input.LA(1)
            if not(_la==19 or _la==20):
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


        def getRuleIndex(self):
            return dAngrParser.RULE_object

     
        def copyFrom(self, ctx:ParserRuleContext):
            super().copyFrom(ctx)


    class SlideStartLengthObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)
        def index(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IndexContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IndexContext,i)

        def ARROW(self):
            return self.getToken(dAngrParser.ARROW, 0)
        def KET(self):
            return self.getToken(dAngrParser.KET, 0)
        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSlideStartLengthObject" ):
                listener.enterSlideStartLengthObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSlideStartLengthObject" ):
                listener.exitSlideStartLengthObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSlideStartLengthObject" ):
                return visitor.visitSlideStartLengthObject(self)
            else:
                return visitor.visitChildren(self)


    class ReferenceObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def reference(self):
            return self.getTypedRuleContext(dAngrParser.ReferenceContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterReferenceObject" ):
                listener.enterReferenceObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitReferenceObject" ):
                listener.exitReferenceObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitReferenceObject" ):
                return visitor.visitReferenceObject(self)
            else:
                return visitor.visitChildren(self)


    class BinaryStringObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def BINARY_STRING(self):
            return self.getToken(dAngrParser.BINARY_STRING, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBinaryStringObject" ):
                listener.enterBinaryStringObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBinaryStringObject" ):
                listener.exitBinaryStringObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBinaryStringObject" ):
                return visitor.visitBinaryStringObject(self)
            else:
                return visitor.visitChildren(self)


    class ListObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)
        def KET(self):
            return self.getToken(dAngrParser.KET, 0)
        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)
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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterListObject" ):
                listener.enterListObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitListObject" ):
                listener.exitListObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitListObject" ):
                return visitor.visitListObject(self)
            else:
                return visitor.visitChildren(self)


    class IndexedPropertyObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)
        def index(self):
            return self.getTypedRuleContext(dAngrParser.IndexContext,0)

        def KET(self):
            return self.getToken(dAngrParser.KET, 0)
        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIndexedPropertyObject" ):
                listener.enterIndexedPropertyObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIndexedPropertyObject" ):
                listener.exitIndexedPropertyObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIndexedPropertyObject" ):
                return visitor.visitIndexedPropertyObject(self)
            else:
                return visitor.visitChildren(self)


    class DictionaryObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def BRACE(self):
            return self.getToken(dAngrParser.BRACE, 0)
        def KETCE(self):
            return self.getToken(dAngrParser.KETCE, 0)
        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)
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

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterDictionaryObject" ):
                listener.enterDictionaryObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitDictionaryObject" ):
                listener.exitDictionaryObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitDictionaryObject" ):
                return visitor.visitDictionaryObject(self)
            else:
                return visitor.visitChildren(self)


    class NumericObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def numeric(self):
            return self.getTypedRuleContext(dAngrParser.NumericContext,0)

        def DASH(self):
            return self.getToken(dAngrParser.DASH, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterNumericObject" ):
                listener.enterNumericObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitNumericObject" ):
                listener.exitNumericObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitNumericObject" ):
                return visitor.visitNumericObject(self)
            else:
                return visitor.visitChildren(self)


    class SliceStartEndObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)

        def BRA(self):
            return self.getToken(dAngrParser.BRA, 0)
        def index(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(dAngrParser.IndexContext)
            else:
                return self.getTypedRuleContext(dAngrParser.IndexContext,i)

        def COLON(self):
            return self.getToken(dAngrParser.COLON, 0)
        def KET(self):
            return self.getToken(dAngrParser.KET, 0)
        def WS(self, i:int=None):
            if i is None:
                return self.getTokens(dAngrParser.WS)
            else:
                return self.getToken(dAngrParser.WS, i)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSliceStartEndObject" ):
                listener.enterSliceStartEndObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSliceStartEndObject" ):
                listener.exitSliceStartEndObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitSliceStartEndObject" ):
                return visitor.visitSliceStartEndObject(self)
            else:
                return visitor.visitChildren(self)


    class StringObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def STRING(self):
            return self.getToken(dAngrParser.STRING, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterStringObject" ):
                listener.enterStringObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitStringObject" ):
                listener.exitStringObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitStringObject" ):
                return visitor.visitStringObject(self)
            else:
                return visitor.visitChildren(self)


    class IDObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIDObject" ):
                listener.enterIDObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIDObject" ):
                listener.exitIDObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitIDObject" ):
                return visitor.visitIDObject(self)
            else:
                return visitor.visitChildren(self)


    class PropertyObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def object_(self):
            return self.getTypedRuleContext(dAngrParser.ObjectContext,0)

        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)
        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPropertyObject" ):
                listener.enterPropertyObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPropertyObject" ):
                listener.exitPropertyObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPropertyObject" ):
                return visitor.visitPropertyObject(self)
            else:
                return visitor.visitChildren(self)


    class BoolObjectContext(ObjectContext):

        def __init__(self, parser, ctx:ParserRuleContext): # actually a dAngrParser.ObjectContext
            super().__init__(parser)
            self.copyFrom(ctx)

        def BOOL(self):
            return self.getToken(dAngrParser.BOOL, 0)

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterBoolObject" ):
                listener.enterBoolObject(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitBoolObject" ):
                listener.exitBoolObject(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitBoolObject" ):
                return visitor.visitBoolObject(self)
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
            self.state = 528
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,87,self._ctx)
            if la_ == 1:
                localctx = dAngrParser.IDObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx

                self.state = 453
                self.identifier()
                self.state = 455
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,70,self._ctx)
                if la_ == 1:
                    self.state = 454
                    self.match(dAngrParser.BANG)


                pass

            elif la_ == 2:
                localctx = dAngrParser.NumericObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 458
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==76:
                    self.state = 457
                    self.match(dAngrParser.DASH)


                self.state = 460
                self.numeric()
                pass

            elif la_ == 3:
                localctx = dAngrParser.BoolObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 461
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 4:
                localctx = dAngrParser.ReferenceObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 462
                self.reference()
                pass

            elif la_ == 5:
                localctx = dAngrParser.ListObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 463
                self.match(dAngrParser.BRA)
                self.state = 465
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,72,self._ctx)
                if la_ == 1:
                    self.state = 464
                    self.match(dAngrParser.WS)


                self.state = 468
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if (((_la) & ~0x3f) == 0 and ((1 << _la) & 2814751903711230) != 0) or _la==75 or _la==76:
                    self.state = 467
                    self.object_(0)


                self.state = 480
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,76,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 471
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 470
                            self.match(dAngrParser.WS)


                        self.state = 473
                        self.match(dAngrParser.COMMA)
                        self.state = 475
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 474
                            self.match(dAngrParser.WS)


                        self.state = 477
                        self.object_(0) 
                    self.state = 482
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,76,self._ctx)

                self.state = 484
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 483
                    self.match(dAngrParser.WS)


                self.state = 486
                self.match(dAngrParser.KET)
                pass

            elif la_ == 6:
                localctx = dAngrParser.DictionaryObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 487
                self.match(dAngrParser.BRACE)
                self.state = 489
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,78,self._ctx)
                if la_ == 1:
                    self.state = 488
                    self.match(dAngrParser.WS)


                self.state = 519
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==29:
                    self.state = 491
                    self.match(dAngrParser.STRING)
                    self.state = 493
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 492
                        self.match(dAngrParser.WS)


                    self.state = 495
                    self.match(dAngrParser.COLON)
                    self.state = 497
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 496
                        self.match(dAngrParser.WS)


                    self.state = 499
                    self.object_(0)

                    self.state = 501
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 500
                        self.match(dAngrParser.WS)


                    self.state = 503
                    self.match(dAngrParser.COMMA)
                    self.state = 505
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 504
                        self.match(dAngrParser.WS)


                    self.state = 507
                    self.match(dAngrParser.STRING)
                    self.state = 509
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 508
                        self.match(dAngrParser.WS)


                    self.state = 511
                    self.match(dAngrParser.COLON)
                    self.state = 513
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 512
                        self.match(dAngrParser.WS)


                    self.state = 515
                    self.object_(0)
                    self.state = 521
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 523
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 522
                    self.match(dAngrParser.WS)


                self.state = 525
                self.match(dAngrParser.KETCE)
                pass

            elif la_ == 7:
                localctx = dAngrParser.StringObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 526
                self.match(dAngrParser.STRING)
                pass

            elif la_ == 8:
                localctx = dAngrParser.BinaryStringObjectContext(self, localctx)
                self._ctx = localctx
                _prevctx = localctx
                self.state = 527
                self.match(dAngrParser.BINARY_STRING)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 586
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,100,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 584
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,99,self._ctx)
                    if la_ == 1:
                        localctx = dAngrParser.PropertyObjectContext(self, dAngrParser.ObjectContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 530
                        if not self.precpred(self._ctx, 8):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 8)")
                        self.state = 531
                        self.match(dAngrParser.DOT)
                        self.state = 532
                        self.identifier()
                        pass

                    elif la_ == 2:
                        localctx = dAngrParser.IndexedPropertyObjectContext(self, dAngrParser.ObjectContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 533
                        if not self.precpred(self._ctx, 7):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 7)")
                        self.state = 534
                        self.match(dAngrParser.BRA)
                        self.state = 536
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 535
                            self.match(dAngrParser.WS)


                        self.state = 538
                        self.index()
                        self.state = 540
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 539
                            self.match(dAngrParser.WS)


                        self.state = 542
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 3:
                        localctx = dAngrParser.SliceStartEndObjectContext(self, dAngrParser.ObjectContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 544
                        if not self.precpred(self._ctx, 6):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                        self.state = 545
                        self.match(dAngrParser.BRA)
                        self.state = 547
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 546
                            self.match(dAngrParser.WS)


                        self.state = 549
                        self.index()
                        self.state = 551
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 550
                            self.match(dAngrParser.WS)


                        self.state = 553
                        self.match(dAngrParser.COLON)
                        self.state = 555
                        self._errHandler.sync(self)
                        la_ = self._interp.adaptivePredict(self._input,92,self._ctx)
                        if la_ == 1:
                            self.state = 554
                            self.match(dAngrParser.WS)


                        self.state = 558
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if (((_la) & ~0x3f) == 0 and ((1 << _la) & 291047120920248318) != 0) or _la==75 or _la==76:
                            self.state = 557
                            self.index()


                        self.state = 561
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 560
                            self.match(dAngrParser.WS)


                        self.state = 563
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 4:
                        localctx = dAngrParser.SlideStartLengthObjectContext(self, dAngrParser.ObjectContext(self, _parentctx, _parentState))
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 565
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 566
                        self.match(dAngrParser.BRA)
                        self.state = 568
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 567
                            self.match(dAngrParser.WS)


                        self.state = 570
                        self.index()
                        self.state = 572
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 571
                            self.match(dAngrParser.WS)


                        self.state = 574
                        self.match(dAngrParser.ARROW)
                        self.state = 576
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 575
                            self.match(dAngrParser.WS)


                        self.state = 578
                        self.index()
                        self.state = 580
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 579
                            self.match(dAngrParser.WS)


                        self.state = 582
                        self.match(dAngrParser.KET)
                        pass

             
                self.state = 588
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,100,self._ctx)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.unrollRecursionContexts(_parentctx)
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

        def BINARY_STRING(self):
            return self.getToken(dAngrParser.BINARY_STRING, 0)

        def WS(self):
            return self.getToken(dAngrParser.WS, 0)

        def LPAREN(self):
            return self.getToken(dAngrParser.LPAREN, 0)

        def anything(self):
            return self.getTypedRuleContext(dAngrParser.AnythingContext,0)


        def RPAREN(self):
            return self.getToken(dAngrParser.RPAREN, 0)

        def special_words(self):
            return self.getTypedRuleContext(dAngrParser.Special_wordsContext,0)


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
        self.enterRule(localctx, 48, self.RULE_anything)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 600
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,101,self._ctx)
            if la_ == 1:
                self.state = 589
                self.match(dAngrParser.LETTERS)
                pass

            elif la_ == 2:
                self.state = 590
                self.match(dAngrParser.NUMBERS)
                pass

            elif la_ == 3:
                self.state = 591
                self.symbol()
                pass

            elif la_ == 4:
                self.state = 592
                self.match(dAngrParser.STRING)
                pass

            elif la_ == 5:
                self.state = 593
                self.match(dAngrParser.BINARY_STRING)
                pass

            elif la_ == 6:
                self.state = 594
                self.match(dAngrParser.WS)
                pass

            elif la_ == 7:
                self.state = 595
                self.match(dAngrParser.LPAREN)
                self.state = 596
                self.anything()
                self.state = 597
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 8:
                self.state = 599
                self.special_words()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
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

        def BREAK(self):
            return self.getToken(dAngrParser.BREAK, 0)

        def CONTINUE(self):
            return self.getToken(dAngrParser.CONTINUE, 0)

        def RANGE(self):
            return self.getToken(dAngrParser.RANGE, 0)

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
            self.state = 602
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 131070) != 0)):
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

        def dangr_range(self):
            return self.getTypedRuleContext(dAngrParser.Dangr_rangeContext,0)


        def bash_range(self):
            return self.getTypedRuleContext(dAngrParser.Bash_rangeContext,0)


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
            self.state = 607
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [39]:
                self.enterOuterAlt(localctx, 1)
                self.state = 604
                self.dangr_range()
                pass
            elif token in [40]:
                self.enterOuterAlt(localctx, 2)
                self.state = 605
                self.bash_range()
                pass
            elif token in [38]:
                self.enterOuterAlt(localctx, 3)
                self.state = 606
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
            self.state = 609
            self.match(dAngrParser.AMP)
            self.state = 610
            self.match(dAngrParser.LPAREN)
            self.state = 611
            self.expression()
            self.state = 612
            self.match(dAngrParser.RPAREN)
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
        self.enterRule(localctx, 56, self.RULE_bash_range)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 614
            self.match(dAngrParser.DOLLAR)
            self.state = 615
            self.match(dAngrParser.LPAREN)
            self.state = 616
            self.bash_content()
            self.state = 617
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
            self.state = 619
            self.match(dAngrParser.BANG)
            self.state = 620
            self.match(dAngrParser.LPAREN)
            self.state = 621
            self.py_content()
            self.state = 622
            self.match(dAngrParser.RPAREN)
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
        self.enterRule(localctx, 60, self.RULE_symbol)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 624
            _la = self._input.LA(1)
            if not(((((_la - 18)) & ~0x3f) == 0 and ((1 << (_la - 18)) & 576460752302374913) != 0)):
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
        self._predicates[3] = self.expression_part_sempred
        self._predicates[23] = self.object_sempred
        pred = self._predicates.get(ruleIndex, None)
        if pred is None:
            raise Exception("No predicate with index:" + str(ruleIndex))
        else:
            return pred(localctx, predIndex)

    def expression_part_sempred(self, localctx:Expression_partContext, predIndex:int):
            if predIndex == 0:
                return self.precpred(self._ctx, 6)
         

    def object_sempred(self, localctx:ObjectContext, predIndex:int):
            if predIndex == 1:
                return self.precpred(self._ctx, 8)
         

            if predIndex == 2:
                return self.precpred(self._ctx, 7)
         

            if predIndex == 3:
                return self.precpred(self._ctx, 6)
         

            if predIndex == 4:
                return self.precpred(self._ctx, 5)
         




