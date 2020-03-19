#include <stdint.h>
#include <stdio.h>

extern int64_t hash(char c, int pos);

int main() {
	printf("{");
	for (char c = 0x20; c < 0x7f; c++) {
		for (int pos = 0; pos < 76; pos++) {
			int64_t h = hash(c, pos);
			printf("%lx:%c,\n", h, c);
		}
	}
	printf("}");
}