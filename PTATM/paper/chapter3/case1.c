int main() {
    int a = 1, b = 2;

	if (a) {
		++b;
	} else {
		b -= a;
	}

	for (int i=0; i<100; ++i) {
		a += i;
		b -= i;
	}

    switch (a) {
		case 0: break;
		case 1: --a; break;
		case 2: a -= 2; break;
		case 3: a -= 3; break;
		case 4: a -= 4; break;
        default: a <<= 1; break;
	}

	return a;
}