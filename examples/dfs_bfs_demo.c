#include <stdio.h>
#include <stdint.h>

static void milestone(const char *tag) {
    // Nice breakpoint target
    printf("MILESTONE: %s\n", tag);
}

int main(void) {
    // Read 3 bytes from stdin (angr can make stdin symbolic)
    uint8_t b0 = 0, b1 = 0, b2 = 0;
    if (fread(&b0, 1, 1, stdin) != 1) return 0;
    if (fread(&b1, 1, 1, stdin) != 1) return 0;
    if (fread(&b2, 1, 1, stdin) != 1) return 0;

    // Depth 1 split
    if ((b0 & 1) == 0) milestone("D1: b0 even");
    else              milestone("D1: b0 odd");

    // Depth 2 split
    if ((b1 & 1) == 0) milestone("D2: b1 even");
    else              milestone("D2: b1 odd");

    // Depth 3 split
    if ((b2 & 1) == 0) milestone("D3: b2 even");
    else              milestone("D3: b2 odd");

    puts("DONE");
    return 0;
}
