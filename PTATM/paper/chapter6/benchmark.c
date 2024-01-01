int case1() {
	int a = 1, b = 2;
	if (a) {
		++b;
	} else {
		b = b - a;
	}
	for (int i=0; i<100; ++i) {
		a = a + i;
		b = b - i;
	}
	switch (a) {
		case 0: break;
		case 1: a = a - 1; break;
		case 2: a = a - 2; break;
		case 3: a = a - 3; break;
		case 4: a = a - 4; break;
		default: a <<= 1; break;
	}
	return a;
}

int case2(int argc) {
	if (argc < 2) {
		return -1;
	}
	int sum = 0;
	for (int i=0; i<100; ++i) {
		sum = sum + i;
	}
	return sum;
}

int case3() {
	int sum = 0;
	for (int i=0; i<100; ++i) {
		if (i % 2) {
			sum += 2*i;
		} else {
			sum = sum + i;
		}
	}
	return sum;
}

int main(int argc, char* argv[]) {
    case1();
    case2(argc);
    case3();
    return 0;
}
