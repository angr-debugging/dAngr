#include <stdio.h>
#include <string.h>

int processMessage(const char* in, int cnt, char* out){
   if (cnt > 0) {printf("count: %d", cnt);}
   int in_len = strlen(in);
   for(int i = 0; i < cnt; ++i){
      for (int j = 0; j< in_len; ++j){
         out[j+i*in_len] = in[j];
      }
   }
   out[cnt * in_len] = '\0'; // Null-terminate the output array after all characters are copied
   printf("p1: %s\n", out);
   return cnt*in_len;
}


int main() {
   char out[2 * 3 + 1]; // Adjusted size to accommodate the result and null terminator
   int i = processMessage("abc", 2, out); // Adjusted cnt parameter to 2
   printf("p2: %s\n", out);
   return 0;
}