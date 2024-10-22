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
        4,1,78,612,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,
        6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,
        2,14,7,14,2,15,7,15,2,16,7,16,2,17,7,17,2,18,7,18,2,19,7,19,2,20,
        7,20,2,21,7,21,2,22,7,22,2,23,7,23,2,24,7,24,2,25,7,25,2,26,7,26,
        2,27,7,27,2,28,7,28,2,29,7,29,2,30,7,30,2,31,7,31,1,0,1,0,1,0,3,
        0,68,8,0,1,0,1,0,1,0,1,0,5,0,74,8,0,10,0,12,0,77,9,0,3,0,79,8,0,
        1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,
        96,8,1,1,2,1,2,1,2,3,2,101,8,2,1,2,1,2,1,2,1,2,1,2,3,2,108,8,2,1,
        2,5,2,111,8,2,10,2,12,2,114,9,2,1,2,1,2,3,2,118,8,2,1,3,1,3,3,3,
        122,8,3,1,3,1,3,3,3,126,8,3,1,3,1,3,3,3,130,8,3,1,3,1,3,3,3,134,
        8,3,1,3,1,3,3,3,138,8,3,1,3,1,3,1,4,1,4,3,4,144,8,4,1,4,1,4,3,4,
        148,8,4,1,4,1,4,1,4,1,4,1,4,1,4,1,4,3,4,157,8,4,1,4,1,4,3,4,161,
        8,4,1,4,1,4,3,4,165,8,4,1,4,3,4,168,8,4,1,5,1,5,3,5,172,8,5,1,5,
        3,5,175,8,5,1,5,1,5,3,5,179,8,5,1,5,1,5,1,6,1,6,1,6,1,6,1,7,1,7,
        1,7,1,7,1,7,1,7,3,7,193,8,7,1,8,1,8,1,8,1,8,3,8,199,8,8,1,8,1,8,
        1,8,3,8,204,8,8,1,8,1,8,1,8,1,8,3,8,210,8,8,1,8,1,8,3,8,214,8,8,
        1,8,3,8,217,8,8,1,8,1,8,1,8,1,8,1,8,3,8,224,8,8,1,8,1,8,1,8,1,8,
        1,8,1,8,1,8,3,8,233,8,8,1,8,1,8,1,8,3,8,238,8,8,1,9,1,9,3,9,242,
        8,9,1,9,1,9,1,9,1,10,1,10,1,10,1,10,3,10,251,8,10,1,10,1,10,3,10,
        255,8,10,1,10,1,10,3,10,259,8,10,1,10,1,10,1,10,1,11,1,11,1,11,3,
        11,267,8,11,4,11,269,8,11,11,11,12,11,270,1,11,1,11,1,12,1,12,1,
        12,1,12,1,12,1,12,3,12,281,8,12,1,13,1,13,1,13,1,13,3,13,287,8,13,
        1,13,1,13,3,13,291,8,13,1,13,1,13,3,13,295,8,13,1,13,1,13,3,13,299,
        8,13,3,13,301,8,13,1,13,1,13,3,13,305,8,13,1,14,1,14,3,14,309,8,
        14,1,14,1,14,3,14,313,8,14,1,14,5,14,316,8,14,10,14,12,14,319,9,
        14,1,15,1,15,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,
        16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,1,16,3,16,342,8,16,1,17,1,
        17,3,17,346,8,17,1,17,1,17,3,17,350,8,17,1,17,5,17,353,8,17,10,17,
        12,17,356,9,17,1,17,1,17,1,18,1,18,1,18,1,18,1,18,1,18,1,18,4,18,
        367,8,18,11,18,12,18,368,1,19,1,19,1,19,1,19,3,19,375,8,19,1,19,
        1,19,1,19,1,19,3,19,381,8,19,1,19,1,19,3,19,385,8,19,1,19,1,19,3,
        19,389,8,19,1,19,3,19,392,8,19,1,19,1,19,3,19,396,8,19,3,19,398,
        8,19,1,20,1,20,1,20,1,20,5,20,404,8,20,10,20,12,20,407,9,20,1,21,
        1,21,3,21,411,8,21,1,22,1,22,1,22,1,22,1,22,3,22,418,8,22,1,22,1,
        22,1,22,1,22,5,22,424,8,22,10,22,12,22,427,9,22,1,23,1,23,1,24,1,
        24,1,24,3,24,434,8,24,1,24,3,24,437,8,24,1,24,1,24,1,24,1,24,1,24,
        1,24,3,24,445,8,24,1,24,1,24,3,24,449,8,24,1,24,1,24,3,24,453,8,
        24,1,24,5,24,456,8,24,10,24,12,24,459,9,24,1,24,3,24,462,8,24,1,
        24,1,24,1,24,1,24,3,24,468,8,24,1,24,1,24,3,24,472,8,24,1,24,1,24,
        3,24,476,8,24,1,24,1,24,3,24,480,8,24,1,24,1,24,3,24,484,8,24,1,
        24,1,24,3,24,488,8,24,1,24,1,24,3,24,492,8,24,1,24,1,24,5,24,496,
        8,24,10,24,12,24,499,9,24,1,24,3,24,502,8,24,1,24,1,24,1,24,3,24,
        507,8,24,1,24,1,24,1,24,1,24,1,24,1,24,3,24,515,8,24,1,24,1,24,3,
        24,519,8,24,1,24,1,24,1,24,1,24,1,24,3,24,526,8,24,1,24,3,24,529,
        8,24,1,24,1,24,3,24,533,8,24,1,24,1,24,3,24,537,8,24,1,24,3,24,540,
        8,24,1,24,1,24,3,24,544,8,24,1,24,1,24,1,24,1,24,1,24,3,24,551,8,
        24,1,24,3,24,554,8,24,1,24,1,24,3,24,558,8,24,1,24,1,24,3,24,562,
        8,24,1,24,3,24,565,8,24,1,24,1,24,3,24,569,8,24,1,24,1,24,5,24,573,
        8,24,10,24,12,24,576,9,24,1,25,1,25,1,26,1,26,1,26,3,26,583,8,26,
        1,27,1,27,1,27,1,27,1,27,1,28,1,28,1,28,1,28,1,28,1,29,1,29,1,29,
        1,29,1,29,1,30,1,30,1,30,1,30,1,30,1,30,1,30,1,30,3,30,608,8,30,
        1,31,1,31,1,31,0,1,48,32,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,
        30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,0,6,2,0,13,13,
        72,72,1,0,24,26,1,0,19,20,2,0,57,57,76,76,1,0,2,16,2,0,18,18,38,
        76,730,0,78,1,0,0,0,2,95,1,0,0,0,4,117,1,0,0,0,6,119,1,0,0,0,8,167,
        1,0,0,0,10,171,1,0,0,0,12,182,1,0,0,0,14,192,1,0,0,0,16,237,1,0,
        0,0,18,239,1,0,0,0,20,246,1,0,0,0,22,263,1,0,0,0,24,280,1,0,0,0,
        26,304,1,0,0,0,28,306,1,0,0,0,30,320,1,0,0,0,32,341,1,0,0,0,34,343,
        1,0,0,0,36,366,1,0,0,0,38,397,1,0,0,0,40,399,1,0,0,0,42,410,1,0,
        0,0,44,417,1,0,0,0,46,428,1,0,0,0,48,506,1,0,0,0,50,577,1,0,0,0,
        52,582,1,0,0,0,54,584,1,0,0,0,56,589,1,0,0,0,58,594,1,0,0,0,60,607,
        1,0,0,0,62,609,1,0,0,0,64,67,7,0,0,0,65,66,5,18,0,0,66,68,3,44,22,
        0,67,65,1,0,0,0,67,68,1,0,0,0,68,69,1,0,0,0,69,79,5,17,0,0,70,74,
        5,17,0,0,71,74,3,2,1,0,72,74,3,20,10,0,73,70,1,0,0,0,73,71,1,0,0,
        0,73,72,1,0,0,0,74,77,1,0,0,0,75,73,1,0,0,0,75,76,1,0,0,0,76,79,
        1,0,0,0,77,75,1,0,0,0,78,64,1,0,0,0,78,75,1,0,0,0,79,80,1,0,0,0,
        80,81,5,0,0,1,81,1,1,0,0,0,82,96,3,16,8,0,83,84,3,10,5,0,84,85,5,
        17,0,0,85,96,1,0,0,0,86,87,3,4,2,0,87,88,5,17,0,0,88,96,1,0,0,0,
        89,90,3,12,6,0,90,91,5,17,0,0,91,96,1,0,0,0,92,93,3,14,7,0,93,94,
        5,17,0,0,94,96,1,0,0,0,95,82,1,0,0,0,95,83,1,0,0,0,95,86,1,0,0,0,
        95,89,1,0,0,0,95,92,1,0,0,0,96,3,1,0,0,0,97,98,3,44,22,0,98,99,5,
        47,0,0,99,101,1,0,0,0,100,97,1,0,0,0,100,101,1,0,0,0,101,102,1,0,
        0,0,102,112,3,44,22,0,103,107,5,18,0,0,104,105,3,44,22,0,105,106,
        5,63,0,0,106,108,1,0,0,0,107,104,1,0,0,0,107,108,1,0,0,0,108,109,
        1,0,0,0,109,111,3,8,4,0,110,103,1,0,0,0,111,114,1,0,0,0,112,110,
        1,0,0,0,112,113,1,0,0,0,113,118,1,0,0,0,114,112,1,0,0,0,115,118,
        3,6,3,0,116,118,3,8,4,0,117,100,1,0,0,0,117,115,1,0,0,0,117,116,
        1,0,0,0,118,5,1,0,0,0,119,121,5,3,0,0,120,122,5,18,0,0,121,120,1,
        0,0,0,121,122,1,0,0,0,122,123,1,0,0,0,123,125,3,30,15,0,124,126,
        5,18,0,0,125,124,1,0,0,0,125,126,1,0,0,0,126,127,1,0,0,0,127,129,
        5,4,0,0,128,130,5,18,0,0,129,128,1,0,0,0,129,130,1,0,0,0,130,131,
        1,0,0,0,131,133,3,8,4,0,132,134,5,18,0,0,133,132,1,0,0,0,133,134,
        1,0,0,0,134,135,1,0,0,0,135,137,5,5,0,0,136,138,5,18,0,0,137,136,
        1,0,0,0,137,138,1,0,0,0,138,139,1,0,0,0,139,140,3,8,4,0,140,7,1,
        0,0,0,141,143,5,36,0,0,142,144,5,18,0,0,143,142,1,0,0,0,143,144,
        1,0,0,0,144,145,1,0,0,0,145,147,3,4,2,0,146,148,5,18,0,0,147,146,
        1,0,0,0,147,148,1,0,0,0,148,149,1,0,0,0,149,150,5,37,0,0,150,168,
        1,0,0,0,151,168,3,52,26,0,152,168,3,38,19,0,153,168,5,12,0,0,154,
        164,3,48,24,0,155,157,5,18,0,0,156,155,1,0,0,0,156,157,1,0,0,0,157,
        158,1,0,0,0,158,160,3,32,16,0,159,161,5,18,0,0,160,159,1,0,0,0,160,
        161,1,0,0,0,161,162,1,0,0,0,162,163,3,4,2,0,163,165,1,0,0,0,164,
        156,1,0,0,0,164,165,1,0,0,0,165,168,1,0,0,0,166,168,3,48,24,0,167,
        141,1,0,0,0,167,151,1,0,0,0,167,152,1,0,0,0,167,153,1,0,0,0,167,
        154,1,0,0,0,167,166,1,0,0,0,168,9,1,0,0,0,169,172,3,12,6,0,170,172,
        3,48,24,0,171,169,1,0,0,0,171,170,1,0,0,0,172,174,1,0,0,0,173,175,
        5,18,0,0,174,173,1,0,0,0,174,175,1,0,0,0,175,176,1,0,0,0,176,178,
        5,63,0,0,177,179,5,18,0,0,178,177,1,0,0,0,178,179,1,0,0,0,179,180,
        1,0,0,0,180,181,3,4,2,0,181,11,1,0,0,0,182,183,5,2,0,0,183,184,5,
        18,0,0,184,185,3,44,22,0,185,13,1,0,0,0,186,187,5,38,0,0,187,193,
        3,34,17,0,188,189,5,39,0,0,189,193,3,4,2,0,190,191,5,40,0,0,191,
        193,3,40,20,0,192,186,1,0,0,0,192,188,1,0,0,0,192,190,1,0,0,0,193,
        15,1,0,0,0,194,195,5,7,0,0,195,196,5,18,0,0,196,198,3,30,15,0,197,
        199,5,18,0,0,198,197,1,0,0,0,198,199,1,0,0,0,199,200,1,0,0,0,200,
        201,5,41,0,0,201,203,3,22,11,0,202,204,3,18,9,0,203,202,1,0,0,0,
        203,204,1,0,0,0,204,238,1,0,0,0,205,206,5,9,0,0,206,207,5,18,0,0,
        207,216,3,44,22,0,208,210,5,18,0,0,209,208,1,0,0,0,209,210,1,0,0,
        0,210,211,1,0,0,0,211,213,5,43,0,0,212,214,5,18,0,0,213,212,1,0,
        0,0,213,214,1,0,0,0,214,215,1,0,0,0,215,217,3,44,22,0,216,209,1,
        0,0,0,216,217,1,0,0,0,217,218,1,0,0,0,218,219,5,18,0,0,219,220,5,
        10,0,0,220,221,5,18,0,0,221,223,3,26,13,0,222,224,5,18,0,0,223,222,
        1,0,0,0,223,224,1,0,0,0,224,225,1,0,0,0,225,226,5,41,0,0,226,227,
        3,22,11,0,227,238,1,0,0,0,228,229,5,11,0,0,229,230,5,18,0,0,230,
        232,3,30,15,0,231,233,5,18,0,0,232,231,1,0,0,0,232,233,1,0,0,0,233,
        234,1,0,0,0,234,235,5,41,0,0,235,236,3,22,11,0,236,238,1,0,0,0,237,
        194,1,0,0,0,237,205,1,0,0,0,237,228,1,0,0,0,238,17,1,0,0,0,239,241,
        5,8,0,0,240,242,5,18,0,0,241,240,1,0,0,0,241,242,1,0,0,0,242,243,
        1,0,0,0,243,244,5,41,0,0,244,245,3,22,11,0,245,19,1,0,0,0,246,247,
        5,6,0,0,247,248,5,18,0,0,248,250,3,44,22,0,249,251,5,18,0,0,250,
        249,1,0,0,0,250,251,1,0,0,0,251,252,1,0,0,0,252,254,5,36,0,0,253,
        255,3,28,14,0,254,253,1,0,0,0,254,255,1,0,0,0,255,256,1,0,0,0,256,
        258,5,37,0,0,257,259,5,18,0,0,258,257,1,0,0,0,258,259,1,0,0,0,259,
        260,1,0,0,0,260,261,5,41,0,0,261,262,3,22,11,0,262,21,1,0,0,0,263,
        268,5,77,0,0,264,266,3,24,12,0,265,267,5,17,0,0,266,265,1,0,0,0,
        266,267,1,0,0,0,267,269,1,0,0,0,268,264,1,0,0,0,269,270,1,0,0,0,
        270,268,1,0,0,0,270,271,1,0,0,0,271,272,1,0,0,0,272,273,5,78,0,0,
        273,23,1,0,0,0,274,281,5,15,0,0,275,281,5,16,0,0,276,277,5,14,0,
        0,277,278,5,18,0,0,278,281,3,4,2,0,279,281,3,2,1,0,280,274,1,0,0,
        0,280,275,1,0,0,0,280,276,1,0,0,0,280,279,1,0,0,0,281,25,1,0,0,0,
        282,305,3,48,24,0,283,284,5,1,0,0,284,286,5,36,0,0,285,287,5,18,
        0,0,286,285,1,0,0,0,286,287,1,0,0,0,287,288,1,0,0,0,288,290,3,46,
        23,0,289,291,5,18,0,0,290,289,1,0,0,0,290,291,1,0,0,0,291,300,1,
        0,0,0,292,294,5,43,0,0,293,295,5,18,0,0,294,293,1,0,0,0,294,295,
        1,0,0,0,295,296,1,0,0,0,296,298,3,46,23,0,297,299,5,18,0,0,298,297,
        1,0,0,0,298,299,1,0,0,0,299,301,1,0,0,0,300,292,1,0,0,0,300,301,
        1,0,0,0,301,302,1,0,0,0,302,303,5,37,0,0,303,305,1,0,0,0,304,282,
        1,0,0,0,304,283,1,0,0,0,305,27,1,0,0,0,306,317,3,44,22,0,307,309,
        5,18,0,0,308,307,1,0,0,0,308,309,1,0,0,0,309,310,1,0,0,0,310,312,
        5,43,0,0,311,313,5,18,0,0,312,311,1,0,0,0,312,313,1,0,0,0,313,314,
        1,0,0,0,314,316,3,44,22,0,315,308,1,0,0,0,316,319,1,0,0,0,317,315,
        1,0,0,0,317,318,1,0,0,0,318,29,1,0,0,0,319,317,1,0,0,0,320,321,3,
        4,2,0,321,31,1,0,0,0,322,342,5,57,0,0,323,342,5,76,0,0,324,342,5,
        56,0,0,325,342,5,58,0,0,326,342,5,55,0,0,327,342,5,62,0,0,328,342,
        5,64,0,0,329,342,5,65,0,0,330,342,5,67,0,0,331,342,5,66,0,0,332,
        342,5,68,0,0,333,342,5,69,0,0,334,342,5,70,0,0,335,336,5,71,0,0,
        336,342,5,59,0,0,337,342,5,60,0,0,338,342,5,61,0,0,339,342,5,39,
        0,0,340,342,5,48,0,0,341,322,1,0,0,0,341,323,1,0,0,0,341,324,1,0,
        0,0,341,325,1,0,0,0,341,326,1,0,0,0,341,327,1,0,0,0,341,328,1,0,
        0,0,341,329,1,0,0,0,341,330,1,0,0,0,341,331,1,0,0,0,341,332,1,0,
        0,0,341,333,1,0,0,0,341,334,1,0,0,0,341,335,1,0,0,0,341,337,1,0,
        0,0,341,338,1,0,0,0,341,339,1,0,0,0,341,340,1,0,0,0,342,33,1,0,0,
        0,343,345,3,44,22,0,344,346,5,18,0,0,345,344,1,0,0,0,345,346,1,0,
        0,0,346,347,1,0,0,0,347,349,5,36,0,0,348,350,5,18,0,0,349,348,1,
        0,0,0,349,350,1,0,0,0,350,354,1,0,0,0,351,353,3,36,18,0,352,351,
        1,0,0,0,353,356,1,0,0,0,354,352,1,0,0,0,354,355,1,0,0,0,355,357,
        1,0,0,0,356,354,1,0,0,0,357,358,5,37,0,0,358,35,1,0,0,0,359,367,
        3,38,19,0,360,367,3,52,26,0,361,367,3,60,30,0,362,363,5,36,0,0,363,
        364,3,36,18,0,364,365,5,37,0,0,365,367,1,0,0,0,366,359,1,0,0,0,366,
        360,1,0,0,0,366,361,1,0,0,0,366,362,1,0,0,0,367,368,1,0,0,0,368,
        366,1,0,0,0,368,369,1,0,0,0,369,37,1,0,0,0,370,371,7,1,0,0,371,372,
        5,47,0,0,372,374,3,44,22,0,373,375,5,38,0,0,374,373,1,0,0,0,374,
        375,1,0,0,0,375,398,1,0,0,0,376,398,5,28,0,0,377,378,5,27,0,0,378,
        380,5,49,0,0,379,381,5,18,0,0,380,379,1,0,0,0,380,381,1,0,0,0,381,
        382,1,0,0,0,382,391,3,46,23,0,383,385,5,18,0,0,384,383,1,0,0,0,384,
        385,1,0,0,0,385,386,1,0,0,0,386,388,5,35,0,0,387,389,5,18,0,0,388,
        387,1,0,0,0,388,389,1,0,0,0,389,390,1,0,0,0,390,392,5,20,0,0,391,
        384,1,0,0,0,391,392,1,0,0,0,392,393,1,0,0,0,393,395,5,50,0,0,394,
        396,5,38,0,0,395,394,1,0,0,0,395,396,1,0,0,0,396,398,1,0,0,0,397,
        370,1,0,0,0,397,376,1,0,0,0,397,377,1,0,0,0,398,39,1,0,0,0,399,405,
        3,44,22,0,400,404,3,52,26,0,401,404,3,60,30,0,402,404,3,38,19,0,
        403,400,1,0,0,0,403,401,1,0,0,0,403,402,1,0,0,0,404,407,1,0,0,0,
        405,403,1,0,0,0,405,406,1,0,0,0,406,41,1,0,0,0,407,405,1,0,0,0,408,
        411,3,44,22,0,409,411,3,46,23,0,410,408,1,0,0,0,410,409,1,0,0,0,
        411,43,1,0,0,0,412,418,5,22,0,0,413,418,5,75,0,0,414,415,3,50,25,
        0,415,416,5,75,0,0,416,418,1,0,0,0,417,412,1,0,0,0,417,413,1,0,0,
        0,417,414,1,0,0,0,418,425,1,0,0,0,419,424,5,22,0,0,420,424,5,20,
        0,0,421,424,5,75,0,0,422,424,3,50,25,0,423,419,1,0,0,0,423,420,1,
        0,0,0,423,421,1,0,0,0,423,422,1,0,0,0,424,427,1,0,0,0,425,423,1,
        0,0,0,425,426,1,0,0,0,426,45,1,0,0,0,427,425,1,0,0,0,428,429,7,2,
        0,0,429,47,1,0,0,0,430,431,6,24,-1,0,431,433,3,44,22,0,432,434,5,
        38,0,0,433,432,1,0,0,0,433,434,1,0,0,0,434,507,1,0,0,0,435,437,7,
        3,0,0,436,435,1,0,0,0,436,437,1,0,0,0,437,438,1,0,0,0,438,507,5,
        20,0,0,439,507,5,19,0,0,440,507,5,12,0,0,441,507,3,38,19,0,442,444,
        5,49,0,0,443,445,5,18,0,0,444,443,1,0,0,0,444,445,1,0,0,0,445,446,
        1,0,0,0,446,457,3,48,24,0,447,449,5,18,0,0,448,447,1,0,0,0,448,449,
        1,0,0,0,449,450,1,0,0,0,450,452,5,43,0,0,451,453,5,18,0,0,452,451,
        1,0,0,0,452,453,1,0,0,0,453,454,1,0,0,0,454,456,3,48,24,0,455,448,
        1,0,0,0,456,459,1,0,0,0,457,455,1,0,0,0,457,458,1,0,0,0,458,461,
        1,0,0,0,459,457,1,0,0,0,460,462,5,18,0,0,461,460,1,0,0,0,461,462,
        1,0,0,0,462,463,1,0,0,0,463,464,5,50,0,0,464,507,1,0,0,0,465,467,
        5,51,0,0,466,468,5,18,0,0,467,466,1,0,0,0,467,468,1,0,0,0,468,497,
        1,0,0,0,469,471,5,29,0,0,470,472,5,18,0,0,471,470,1,0,0,0,471,472,
        1,0,0,0,472,473,1,0,0,0,473,475,5,41,0,0,474,476,5,18,0,0,475,474,
        1,0,0,0,475,476,1,0,0,0,476,477,1,0,0,0,477,479,3,48,24,0,478,480,
        5,18,0,0,479,478,1,0,0,0,479,480,1,0,0,0,480,481,1,0,0,0,481,483,
        5,43,0,0,482,484,5,18,0,0,483,482,1,0,0,0,483,484,1,0,0,0,484,485,
        1,0,0,0,485,487,5,29,0,0,486,488,5,18,0,0,487,486,1,0,0,0,487,488,
        1,0,0,0,488,489,1,0,0,0,489,491,5,41,0,0,490,492,5,18,0,0,491,490,
        1,0,0,0,491,492,1,0,0,0,492,493,1,0,0,0,493,494,3,48,24,0,494,496,
        1,0,0,0,495,469,1,0,0,0,496,499,1,0,0,0,497,495,1,0,0,0,497,498,
        1,0,0,0,498,501,1,0,0,0,499,497,1,0,0,0,500,502,5,18,0,0,501,500,
        1,0,0,0,501,502,1,0,0,0,502,503,1,0,0,0,503,507,5,52,0,0,504,507,
        5,29,0,0,505,507,5,32,0,0,506,430,1,0,0,0,506,436,1,0,0,0,506,439,
        1,0,0,0,506,440,1,0,0,0,506,441,1,0,0,0,506,442,1,0,0,0,506,465,
        1,0,0,0,506,504,1,0,0,0,506,505,1,0,0,0,507,574,1,0,0,0,508,509,
        10,8,0,0,509,510,5,47,0,0,510,573,3,44,22,0,511,512,10,7,0,0,512,
        514,5,49,0,0,513,515,5,18,0,0,514,513,1,0,0,0,514,515,1,0,0,0,515,
        516,1,0,0,0,516,518,3,42,21,0,517,519,5,18,0,0,518,517,1,0,0,0,518,
        519,1,0,0,0,519,520,1,0,0,0,520,521,5,50,0,0,521,573,1,0,0,0,522,
        523,10,6,0,0,523,525,5,49,0,0,524,526,5,18,0,0,525,524,1,0,0,0,525,
        526,1,0,0,0,526,528,1,0,0,0,527,529,5,76,0,0,528,527,1,0,0,0,528,
        529,1,0,0,0,529,530,1,0,0,0,530,532,3,46,23,0,531,533,5,18,0,0,532,
        531,1,0,0,0,532,533,1,0,0,0,533,534,1,0,0,0,534,536,5,41,0,0,535,
        537,5,18,0,0,536,535,1,0,0,0,536,537,1,0,0,0,537,539,1,0,0,0,538,
        540,5,76,0,0,539,538,1,0,0,0,539,540,1,0,0,0,540,541,1,0,0,0,541,
        543,3,46,23,0,542,544,5,18,0,0,543,542,1,0,0,0,543,544,1,0,0,0,544,
        545,1,0,0,0,545,546,5,50,0,0,546,573,1,0,0,0,547,548,10,5,0,0,548,
        550,5,49,0,0,549,551,5,18,0,0,550,549,1,0,0,0,550,551,1,0,0,0,551,
        553,1,0,0,0,552,554,5,76,0,0,553,552,1,0,0,0,553,554,1,0,0,0,554,
        555,1,0,0,0,555,557,3,46,23,0,556,558,5,18,0,0,557,556,1,0,0,0,557,
        558,1,0,0,0,558,559,1,0,0,0,559,561,5,35,0,0,560,562,5,18,0,0,561,
        560,1,0,0,0,561,562,1,0,0,0,562,564,1,0,0,0,563,565,5,76,0,0,564,
        563,1,0,0,0,564,565,1,0,0,0,565,566,1,0,0,0,566,568,5,20,0,0,567,
        569,5,18,0,0,568,567,1,0,0,0,568,569,1,0,0,0,569,570,1,0,0,0,570,
        571,5,50,0,0,571,573,1,0,0,0,572,508,1,0,0,0,572,511,1,0,0,0,572,
        522,1,0,0,0,572,547,1,0,0,0,573,576,1,0,0,0,574,572,1,0,0,0,574,
        575,1,0,0,0,575,49,1,0,0,0,576,574,1,0,0,0,577,578,7,4,0,0,578,51,
        1,0,0,0,579,583,3,54,27,0,580,583,3,56,28,0,581,583,3,58,29,0,582,
        579,1,0,0,0,582,580,1,0,0,0,582,581,1,0,0,0,583,53,1,0,0,0,584,585,
        5,40,0,0,585,586,5,36,0,0,586,587,3,40,20,0,587,588,5,37,0,0,588,
        55,1,0,0,0,589,590,5,39,0,0,590,591,5,36,0,0,591,592,3,4,2,0,592,
        593,5,37,0,0,593,57,1,0,0,0,594,595,5,38,0,0,595,596,5,36,0,0,596,
        597,3,36,18,0,597,598,5,37,0,0,598,59,1,0,0,0,599,608,5,22,0,0,600,
        608,5,20,0,0,601,608,3,62,31,0,602,608,5,29,0,0,603,604,5,36,0,0,
        604,605,3,60,30,0,605,606,5,37,0,0,606,608,1,0,0,0,607,599,1,0,0,
        0,607,600,1,0,0,0,607,601,1,0,0,0,607,602,1,0,0,0,607,603,1,0,0,
        0,608,61,1,0,0,0,609,610,7,5,0,0,610,63,1,0,0,0,102,67,73,75,78,
        95,100,107,112,117,121,125,129,133,137,143,147,156,160,164,167,171,
        174,178,192,198,203,209,213,216,223,232,237,241,250,254,258,266,
        270,280,286,290,294,298,300,304,308,312,317,341,345,349,354,366,
        368,374,380,384,388,391,395,397,403,405,410,417,423,425,433,436,
        444,448,452,457,461,467,471,475,479,483,487,491,497,501,506,514,
        518,525,528,532,536,539,543,550,553,557,561,564,568,572,574,582,
        607
    ]

class dAngrParser ( Parser ):

    grammarFileName = "dAngr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'range'", "'static'", "'IIF'", "'THEN'", 
                     "'ELSE'", "'def'", "'if'", "'else'", "'for'", "'in'", 
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
                     "'-'" ]

    symbolicNames = [ "<INVALID>", "<INVALID>", "STATIC", "CIF", "CTHEN", 
                      "CELSE", "DEF", "IF", "ELSE", "FOR", "IN", "WHILE", 
                      "BOOL", "HELP", "RETURN", "BREAK", "CONTINUE", "NEWLINE", 
                      "WS", "HEX_NUMBERS", "NUMBERS", "NUMBER", "LETTERS", 
                      "LETTER", "SYM_DB", "REG_DB", "VARS_DB", "MEM_DB", 
                      "STATE", "STRING", "ESCAPED_QUOTE", "ESCAPED_SINGLE_QUOTE", 
                      "BINARY_STRING", "SESC_SEQ", "ESC_SEQ", "ARROW", "LPAREN", 
                      "RPAREN", "BANG", "AMP", "DOLLAR", "COLON", "SCOLON", 
                      "COMMA", "QUOTE", "SQUOTE", "AT", "DOT", "BAR", "BRA", 
                      "KET", "BRACE", "KETCE", "HAT", "HASH", "PERC", "MUL", 
                      "ADD", "DIV", "FLOORDIV", "LSHIFT", "RSHIFT", "POW", 
                      "ASSIGN", "EQ", "NEQ", "LT", "GT", "LE", "GE", "AND", 
                      "OR", "QMARK", "TILDE", "TICK", "UNDERSCORE", "DASH", 
                      "INDENT", "DEDENT" ]

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
    ESCAPED_QUOTE=30
    ESCAPED_SINGLE_QUOTE=31
    BINARY_STRING=32
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
    INDENT=77
    DEDENT=78

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
                if not(_la==13 or _la==72):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 67
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
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
                while (((_la) & ~0x3f) == 0 and ((1 << _la) & 146931936065748988) != 0) or _la==75 or _la==76:
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


        def DOT(self):
            return self.getToken(dAngrParser.DOT, 0)

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
            self.state = 117
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,8,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 100
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
                if la_ == 1:
                    self.state = 97
                    self.identifier()
                    self.state = 98
                    self.match(dAngrParser.DOT)


                self.state = 102
                self.identifier()
                self.state = 112
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,7,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 103
                        self.match(dAngrParser.WS)
                        self.state = 107
                        self._errHandler.sync(self)
                        la_ = self._interp.adaptivePredict(self._input,6,self._ctx)
                        if la_ == 1:
                            self.state = 104
                            self.identifier()
                            self.state = 105
                            self.match(dAngrParser.ASSIGN)


                        self.state = 109
                        self.expression_part() 
                    self.state = 114
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,7,self._ctx)

                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 115
                self.constraint()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 116
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
            self.state = 119
            self.match(dAngrParser.CIF)
            self.state = 121
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 120
                self.match(dAngrParser.WS)


            self.state = 123
            self.condition()
            self.state = 125
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 124
                self.match(dAngrParser.WS)


            self.state = 127
            self.match(dAngrParser.CTHEN)
            self.state = 129
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 128
                self.match(dAngrParser.WS)


            self.state = 131
            self.expression_part()
            self.state = 133
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 132
                self.match(dAngrParser.WS)


            self.state = 135
            self.match(dAngrParser.CELSE)
            self.state = 137
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 136
                self.match(dAngrParser.WS)


            self.state = 139
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
            self.state = 167
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,19,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 141
                self.match(dAngrParser.LPAREN)
                self.state = 143
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 142
                    self.match(dAngrParser.WS)


                self.state = 145
                self.expression()
                self.state = 147
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 146
                    self.match(dAngrParser.WS)


                self.state = 149
                self.match(dAngrParser.RPAREN)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 151
                self.range_()
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 152
                self.reference()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 153
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 154
                self.object_(0)
                self.state = 164
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,18,self._ctx)
                if la_ == 1:
                    self.state = 156
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 155
                        self.match(dAngrParser.WS)


                    self.state = 158
                    self.operation()
                    self.state = 160
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 159
                        self.match(dAngrParser.WS)


                    self.state = 162
                    self.expression()


                pass

            elif la_ == 6:
                self.enterOuterAlt(localctx, 6)
                self.state = 166
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
            self.state = 171
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,20,self._ctx)
            if la_ == 1:
                self.state = 169
                self.static_var()
                pass

            elif la_ == 2:
                self.state = 170
                self.object_(0)
                pass


            self.state = 174
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 173
                self.match(dAngrParser.WS)


            self.state = 176
            self.match(dAngrParser.ASSIGN)
            self.state = 178
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 177
                self.match(dAngrParser.WS)


            self.state = 180
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
            self.state = 182
            self.match(dAngrParser.STATIC)
            self.state = 183
            self.match(dAngrParser.WS)
            self.state = 184
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
            self.state = 192
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [38]:
                self.enterOuterAlt(localctx, 1)
                self.state = 186
                self.match(dAngrParser.BANG)
                self.state = 187
                self.py_basic_content()
                pass
            elif token in [39]:
                self.enterOuterAlt(localctx, 2)
                self.state = 188
                self.match(dAngrParser.AMP)
                self.state = 189
                self.expression()
                pass
            elif token in [40]:
                self.enterOuterAlt(localctx, 3)
                self.state = 190
                self.match(dAngrParser.DOLLAR)
                self.state = 191
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
            self.state = 237
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [7]:
                self.enterOuterAlt(localctx, 1)
                self.state = 194
                self.match(dAngrParser.IF)
                self.state = 195
                self.match(dAngrParser.WS)
                self.state = 196
                self.condition()
                self.state = 198
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 197
                    self.match(dAngrParser.WS)


                self.state = 200
                self.match(dAngrParser.COLON)
                self.state = 201
                self.body()
                self.state = 203
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,25,self._ctx)
                if la_ == 1:
                    self.state = 202
                    self.else_()


                pass
            elif token in [9]:
                self.enterOuterAlt(localctx, 2)
                self.state = 205
                self.match(dAngrParser.FOR)
                self.state = 206
                self.match(dAngrParser.WS)
                self.state = 207
                self.identifier()
                self.state = 216
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,28,self._ctx)
                if la_ == 1:
                    self.state = 209
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 208
                        self.match(dAngrParser.WS)


                    self.state = 211
                    self.match(dAngrParser.COMMA)
                    self.state = 213
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 212
                        self.match(dAngrParser.WS)


                    self.state = 215
                    self.identifier()


                self.state = 218
                self.match(dAngrParser.WS)
                self.state = 219
                self.match(dAngrParser.IN)
                self.state = 220
                self.match(dAngrParser.WS)
                self.state = 221
                self.iterable()
                self.state = 223
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 222
                    self.match(dAngrParser.WS)


                self.state = 225
                self.match(dAngrParser.COLON)
                self.state = 226
                self.body()
                pass
            elif token in [11]:
                self.enterOuterAlt(localctx, 3)
                self.state = 228
                self.match(dAngrParser.WHILE)
                self.state = 229
                self.match(dAngrParser.WS)
                self.state = 230
                self.condition()
                self.state = 232
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 231
                    self.match(dAngrParser.WS)


                self.state = 234
                self.match(dAngrParser.COLON)
                self.state = 235
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
            self.state = 239
            self.match(dAngrParser.ELSE)
            self.state = 241
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 240
                self.match(dAngrParser.WS)


            self.state = 243
            self.match(dAngrParser.COLON)
            self.state = 244
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
            self.state = 246
            self.match(dAngrParser.DEF)
            self.state = 247
            self.match(dAngrParser.WS)
            self.state = 248
            self.identifier()
            self.state = 250
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 249
                self.match(dAngrParser.WS)


            self.state = 252
            self.match(dAngrParser.LPAREN)
            self.state = 254
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if (((_la) & ~0x3f) == 0 and ((1 << _la) & 4325372) != 0) or _la==75:
                self.state = 253
                self.parameters()


            self.state = 256
            self.match(dAngrParser.RPAREN)
            self.state = 258
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 257
                self.match(dAngrParser.WS)


            self.state = 260
            self.match(dAngrParser.COLON)
            self.state = 261
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
            self.state = 263
            self.match(dAngrParser.INDENT)
            self.state = 268 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 264
                self.fstatement()
                self.state = 266
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==17:
                    self.state = 265
                    self.match(dAngrParser.NEWLINE)


                self.state = 270 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 146931936065617916) != 0) or _la==75 or _la==76):
                    break

            self.state = 272
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
        self.enterRule(localctx, 24, self.RULE_fstatement)
        try:
            self.state = 280
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,38,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 274
                self.match(dAngrParser.BREAK)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 275
                self.match(dAngrParser.CONTINUE)
                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 276
                self.match(dAngrParser.RETURN)
                self.state = 277
                self.match(dAngrParser.WS)
                self.state = 278
                self.expression()
                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 279
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
            self.state = 304
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 22, 24, 25, 26, 27, 28, 29, 32, 49, 51, 57, 75, 76]:
                self.enterOuterAlt(localctx, 1)
                self.state = 282
                self.object_(0)
                pass
            elif token in [1]:
                self.enterOuterAlt(localctx, 2)
                self.state = 283
                self.match(dAngrParser.T__0)
                self.state = 284
                self.match(dAngrParser.LPAREN)
                self.state = 286
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 285
                    self.match(dAngrParser.WS)


                self.state = 288
                self.numeric()
                self.state = 290
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 289
                    self.match(dAngrParser.WS)


                self.state = 300
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==43:
                    self.state = 292
                    self.match(dAngrParser.COMMA)
                    self.state = 294
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 293
                        self.match(dAngrParser.WS)


                    self.state = 296
                    self.numeric()
                    self.state = 298
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 297
                        self.match(dAngrParser.WS)




                self.state = 302
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
            self.state = 306
            self.identifier()
            self.state = 317
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==18 or _la==43:
                self.state = 308
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 307
                    self.match(dAngrParser.WS)


                self.state = 310
                self.match(dAngrParser.COMMA)
                self.state = 312
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 311
                    self.match(dAngrParser.WS)


                self.state = 314
                self.identifier()
                self.state = 319
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
            self.state = 320
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
            self.state = 341
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [57]:
                self.enterOuterAlt(localctx, 1)
                self.state = 322
                self.match(dAngrParser.ADD)
                pass
            elif token in [76]:
                self.enterOuterAlt(localctx, 2)
                self.state = 323
                self.match(dAngrParser.DASH)
                pass
            elif token in [56]:
                self.enterOuterAlt(localctx, 3)
                self.state = 324
                self.match(dAngrParser.MUL)
                pass
            elif token in [58]:
                self.enterOuterAlt(localctx, 4)
                self.state = 325
                self.match(dAngrParser.DIV)
                pass
            elif token in [55]:
                self.enterOuterAlt(localctx, 5)
                self.state = 326
                self.match(dAngrParser.PERC)
                pass
            elif token in [62]:
                self.enterOuterAlt(localctx, 6)
                self.state = 327
                self.match(dAngrParser.POW)
                pass
            elif token in [64]:
                self.enterOuterAlt(localctx, 7)
                self.state = 328
                self.match(dAngrParser.EQ)
                pass
            elif token in [65]:
                self.enterOuterAlt(localctx, 8)
                self.state = 329
                self.match(dAngrParser.NEQ)
                pass
            elif token in [67]:
                self.enterOuterAlt(localctx, 9)
                self.state = 330
                self.match(dAngrParser.GT)
                pass
            elif token in [66]:
                self.enterOuterAlt(localctx, 10)
                self.state = 331
                self.match(dAngrParser.LT)
                pass
            elif token in [68]:
                self.enterOuterAlt(localctx, 11)
                self.state = 332
                self.match(dAngrParser.LE)
                pass
            elif token in [69]:
                self.enterOuterAlt(localctx, 12)
                self.state = 333
                self.match(dAngrParser.GE)
                pass
            elif token in [70]:
                self.enterOuterAlt(localctx, 13)
                self.state = 334
                self.match(dAngrParser.AND)
                pass
            elif token in [71]:
                self.enterOuterAlt(localctx, 14)
                self.state = 335
                self.match(dAngrParser.OR)
                self.state = 336
                self.match(dAngrParser.FLOORDIV)
                pass
            elif token in [60]:
                self.enterOuterAlt(localctx, 15)
                self.state = 337
                self.match(dAngrParser.LSHIFT)
                pass
            elif token in [61]:
                self.enterOuterAlt(localctx, 16)
                self.state = 338
                self.match(dAngrParser.RSHIFT)
                pass
            elif token in [39]:
                self.enterOuterAlt(localctx, 17)
                self.state = 339
                self.match(dAngrParser.AMP)
                pass
            elif token in [48]:
                self.enterOuterAlt(localctx, 18)
                self.state = 340
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
            self.state = 343
            self.identifier()
            self.state = 345
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==18:
                self.state = 344
                self.match(dAngrParser.WS)


            self.state = 347
            self.match(dAngrParser.LPAREN)
            self.state = 349
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,50,self._ctx)
            if la_ == 1:
                self.state = 348
                self.match(dAngrParser.WS)


            self.state = 354
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 18)) & ~0x3f) == 0 and ((1 << (_la - 18)) & 576460752302641109) != 0):
                self.state = 351
                self.py_content()
                self.state = 356
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 357
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
            self.state = 366 
            self._errHandler.sync(self)
            _alt = 1
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt == 1:
                    self.state = 366
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,52,self._ctx)
                    if la_ == 1:
                        self.state = 359
                        self.reference()
                        pass

                    elif la_ == 2:
                        self.state = 360
                        self.range_()
                        pass

                    elif la_ == 3:
                        self.state = 361
                        self.anything()
                        pass

                    elif la_ == 4:
                        self.state = 362
                        self.match(dAngrParser.LPAREN)
                        self.state = 363
                        self.py_content()
                        self.state = 364
                        self.match(dAngrParser.RPAREN)
                        pass



                else:
                    raise NoViableAltException(self)
                self.state = 368 
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

        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

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
            self.state = 397
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [24, 25, 26]:
                self.enterOuterAlt(localctx, 1)
                self.state = 370
                _la = self._input.LA(1)
                if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 117440512) != 0)):
                    self._errHandler.recoverInline(self)
                else:
                    self._errHandler.reportMatch(self)
                    self.consume()
                self.state = 371
                self.match(dAngrParser.DOT)
                self.state = 372
                self.identifier()
                self.state = 374
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,54,self._ctx)
                if la_ == 1:
                    self.state = 373
                    self.match(dAngrParser.BANG)


                pass
            elif token in [28]:
                self.enterOuterAlt(localctx, 2)
                self.state = 376
                self.match(dAngrParser.STATE)
                pass
            elif token in [27]:
                self.enterOuterAlt(localctx, 3)
                self.state = 377
                self.match(dAngrParser.MEM_DB)
                self.state = 378
                self.match(dAngrParser.BRA)
                self.state = 380
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 379
                    self.match(dAngrParser.WS)


                self.state = 382
                self.numeric()
                self.state = 391
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18 or _la==35:
                    self.state = 384
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 383
                        self.match(dAngrParser.WS)


                    self.state = 386
                    self.match(dAngrParser.ARROW)
                    self.state = 388
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 387
                        self.match(dAngrParser.WS)


                    self.state = 390
                    self.match(dAngrParser.NUMBERS)


                self.state = 393
                self.match(dAngrParser.KET)
                self.state = 395
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,59,self._ctx)
                if la_ == 1:
                    self.state = 394
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
            self.state = 399
            self.identifier()
            self.state = 405
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while ((((_la - 18)) & ~0x3f) == 0 and ((1 << (_la - 18)) & 576460752302641109) != 0):
                self.state = 403
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,61,self._ctx)
                if la_ == 1:
                    self.state = 400
                    self.range_()
                    pass

                elif la_ == 2:
                    self.state = 401
                    self.anything()
                    pass

                elif la_ == 3:
                    self.state = 402
                    self.reference()
                    pass


                self.state = 407
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
            self.state = 410
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 75]:
                self.enterOuterAlt(localctx, 1)
                self.state = 408
                self.identifier()
                pass
            elif token in [19, 20]:
                self.enterOuterAlt(localctx, 2)
                self.state = 409
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
            self.state = 417
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [22]:
                self.state = 412
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [75]:
                self.state = 413
                self.match(dAngrParser.UNDERSCORE)
                pass
            elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                self.state = 414
                self.special_words()
                self.state = 415
                self.match(dAngrParser.UNDERSCORE)
                pass
            else:
                raise NoViableAltException(self)

            self.state = 425
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,66,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    self.state = 423
                    self._errHandler.sync(self)
                    token = self._input.LA(1)
                    if token in [22]:
                        self.state = 419
                        self.match(dAngrParser.LETTERS)
                        pass
                    elif token in [20]:
                        self.state = 420
                        self.match(dAngrParser.NUMBERS)
                        pass
                    elif token in [75]:
                        self.state = 421
                        self.match(dAngrParser.UNDERSCORE)
                        pass
                    elif token in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                        self.state = 422
                        self.special_words()
                        pass
                    else:
                        raise NoViableAltException(self)
             
                self.state = 427
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,66,self._ctx)

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
            self.state = 428
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

        def identifier(self):
            return self.getTypedRuleContext(dAngrParser.IdentifierContext,0)


        def BANG(self):
            return self.getToken(dAngrParser.BANG, 0)

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
            self.state = 506
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,83,self._ctx)
            if la_ == 1:
                self.state = 431
                self.identifier()
                self.state = 433
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,67,self._ctx)
                if la_ == 1:
                    self.state = 432
                    self.match(dAngrParser.BANG)


                pass

            elif la_ == 2:
                self.state = 436
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==57 or _la==76:
                    self.state = 435
                    _la = self._input.LA(1)
                    if not(_la==57 or _la==76):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()


                self.state = 438
                self.match(dAngrParser.NUMBERS)
                pass

            elif la_ == 3:
                self.state = 439
                self.match(dAngrParser.HEX_NUMBERS)
                pass

            elif la_ == 4:
                self.state = 440
                self.match(dAngrParser.BOOL)
                pass

            elif la_ == 5:
                self.state = 441
                self.reference()
                pass

            elif la_ == 6:
                self.state = 442
                self.match(dAngrParser.BRA)
                self.state = 444
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 443
                    self.match(dAngrParser.WS)


                self.state = 446
                self.object_(0)
                self.state = 457
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,72,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 448
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 447
                            self.match(dAngrParser.WS)


                        self.state = 450
                        self.match(dAngrParser.COMMA)
                        self.state = 452
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 451
                            self.match(dAngrParser.WS)


                        self.state = 454
                        self.object_(0) 
                    self.state = 459
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,72,self._ctx)

                self.state = 461
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 460
                    self.match(dAngrParser.WS)


                self.state = 463
                self.match(dAngrParser.KET)
                pass

            elif la_ == 7:
                self.state = 465
                self.match(dAngrParser.BRACE)
                self.state = 467
                self._errHandler.sync(self)
                la_ = self._interp.adaptivePredict(self._input,74,self._ctx)
                if la_ == 1:
                    self.state = 466
                    self.match(dAngrParser.WS)


                self.state = 497
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                while _la==29:
                    self.state = 469
                    self.match(dAngrParser.STRING)
                    self.state = 471
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 470
                        self.match(dAngrParser.WS)


                    self.state = 473
                    self.match(dAngrParser.COLON)
                    self.state = 475
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 474
                        self.match(dAngrParser.WS)


                    self.state = 477
                    self.object_(0)

                    self.state = 479
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 478
                        self.match(dAngrParser.WS)


                    self.state = 481
                    self.match(dAngrParser.COMMA)
                    self.state = 483
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 482
                        self.match(dAngrParser.WS)


                    self.state = 485
                    self.match(dAngrParser.STRING)
                    self.state = 487
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 486
                        self.match(dAngrParser.WS)


                    self.state = 489
                    self.match(dAngrParser.COLON)
                    self.state = 491
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)
                    if _la==18:
                        self.state = 490
                        self.match(dAngrParser.WS)


                    self.state = 493
                    self.object_(0)
                    self.state = 499
                    self._errHandler.sync(self)
                    _la = self._input.LA(1)

                self.state = 501
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==18:
                    self.state = 500
                    self.match(dAngrParser.WS)


                self.state = 503
                self.match(dAngrParser.KETCE)
                pass

            elif la_ == 8:
                self.state = 504
                self.match(dAngrParser.STRING)
                pass

            elif la_ == 9:
                self.state = 505
                self.match(dAngrParser.BINARY_STRING)
                pass


            self._ctx.stop = self._input.LT(-1)
            self.state = 574
            self._errHandler.sync(self)
            _alt = self._interp.adaptivePredict(self._input,99,self._ctx)
            while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                if _alt==1:
                    if self._parseListeners is not None:
                        self.triggerExitRuleEvent()
                    _prevctx = localctx
                    self.state = 572
                    self._errHandler.sync(self)
                    la_ = self._interp.adaptivePredict(self._input,98,self._ctx)
                    if la_ == 1:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 508
                        if not self.precpred(self._ctx, 8):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 8)")
                        self.state = 509
                        self.match(dAngrParser.DOT)
                        self.state = 510
                        self.identifier()
                        pass

                    elif la_ == 2:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 511
                        if not self.precpred(self._ctx, 7):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 7)")
                        self.state = 512
                        self.match(dAngrParser.BRA)
                        self.state = 514
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 513
                            self.match(dAngrParser.WS)


                        self.state = 516
                        self.index()
                        self.state = 518
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 517
                            self.match(dAngrParser.WS)


                        self.state = 520
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 3:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 522
                        if not self.precpred(self._ctx, 6):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 6)")
                        self.state = 523
                        self.match(dAngrParser.BRA)
                        self.state = 525
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 524
                            self.match(dAngrParser.WS)


                        self.state = 528
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==76:
                            self.state = 527
                            self.match(dAngrParser.DASH)


                        self.state = 530
                        self.numeric()
                        self.state = 532
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 531
                            self.match(dAngrParser.WS)


                        self.state = 534
                        self.match(dAngrParser.COLON)
                        self.state = 536
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 535
                            self.match(dAngrParser.WS)


                        self.state = 539
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==76:
                            self.state = 538
                            self.match(dAngrParser.DASH)


                        self.state = 541
                        self.numeric()
                        self.state = 543
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 542
                            self.match(dAngrParser.WS)


                        self.state = 545
                        self.match(dAngrParser.KET)
                        pass

                    elif la_ == 4:
                        localctx = dAngrParser.ObjectContext(self, _parentctx, _parentState)
                        self.pushNewRecursionContext(localctx, _startState, self.RULE_object)
                        self.state = 547
                        if not self.precpred(self._ctx, 5):
                            from antlr4.error.Errors import FailedPredicateException
                            raise FailedPredicateException(self, "self.precpred(self._ctx, 5)")
                        self.state = 548
                        self.match(dAngrParser.BRA)
                        self.state = 550
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 549
                            self.match(dAngrParser.WS)


                        self.state = 553
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==76:
                            self.state = 552
                            self.match(dAngrParser.DASH)


                        self.state = 555
                        self.numeric()
                        self.state = 557
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 556
                            self.match(dAngrParser.WS)


                        self.state = 559
                        self.match(dAngrParser.ARROW)
                        self.state = 561
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 560
                            self.match(dAngrParser.WS)


                        self.state = 564
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==76:
                            self.state = 563
                            self.match(dAngrParser.DASH)


                        self.state = 566
                        self.match(dAngrParser.NUMBERS)
                        self.state = 568
                        self._errHandler.sync(self)
                        _la = self._input.LA(1)
                        if _la==18:
                            self.state = 567
                            self.match(dAngrParser.WS)


                        self.state = 570
                        self.match(dAngrParser.KET)
                        pass

             
                self.state = 576
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,99,self._ctx)

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

        def BREAK(self):
            return self.getToken(dAngrParser.BREAK, 0)

        def CONTINUE(self):
            return self.getToken(dAngrParser.CONTINUE, 0)

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
            self.state = 577
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 131068) != 0)):
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
            self.state = 582
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [40]:
                self.enterOuterAlt(localctx, 1)
                self.state = 579
                self.bash_range()
                pass
            elif token in [39]:
                self.enterOuterAlt(localctx, 2)
                self.state = 580
                self.dangr_range()
                pass
            elif token in [38]:
                self.enterOuterAlt(localctx, 3)
                self.state = 581
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
            self.state = 584
            self.match(dAngrParser.DOLLAR)
            self.state = 585
            self.match(dAngrParser.LPAREN)
            self.state = 586
            self.bash_content()
            self.state = 587
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
            self.state = 589
            self.match(dAngrParser.AMP)
            self.state = 590
            self.match(dAngrParser.LPAREN)
            self.state = 591
            self.expression()
            self.state = 592
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
            self.state = 594
            self.match(dAngrParser.BANG)
            self.state = 595
            self.match(dAngrParser.LPAREN)
            self.state = 596
            self.py_content()
            self.state = 597
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
            self.state = 607
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [22]:
                self.state = 599
                self.match(dAngrParser.LETTERS)
                pass
            elif token in [20]:
                self.state = 600
                self.match(dAngrParser.NUMBERS)
                pass
            elif token in [18, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76]:
                self.state = 601
                self.symbol()
                pass
            elif token in [29]:
                self.state = 602
                self.match(dAngrParser.STRING)
                pass
            elif token in [36]:
                self.state = 603
                self.match(dAngrParser.LPAREN)
                self.state = 604
                self.anything()
                self.state = 605
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
            self.state = 609
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
         




