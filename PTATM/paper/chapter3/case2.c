
int main(int argc, char* argv[]) {
    if (argc < 2) {
        return -1;
    }

    int sum = 0;
    for (int i=0; i<100; ++i) {
        sum += i;
    }

    return sum;
}