#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int func1(int argc) {
    if (argc < 2) {
        return -1;
    } else return 1;
}

int func2(int argc) {
    if (argc < 2) {
        return -5;
    } else return 5;
}

int func3(int argc) {
    if (argc < 2) {
        return 0;
    } else return argc;
}

void caseb(int a, int b) {
    switch (b) {
        case 0: break;
        case 1: --a; break;
        case 2: a -= 2; break;
        case 3: a -= 3; break;
        case 4: a -= 4; break;
        default: a <<= 1; break;
    }

    printf("a = %d\n", a);
}

int main(int argc, char *argv[]) {
    int b = 2, a = argc;

	if (a & 1) {
		b += func1(argc);
	} else {
		b -= func2(argc);
	}

	b += func3(argc);

    caseb(a, b);

    return 0;
}
