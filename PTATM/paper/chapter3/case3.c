
int main(int argc, char* argv[]) {
    int sum = 0;
    for (int i=0; i<100; ++i) {
        if (i % 2) {
            sum += 2*i;
        } else {
            sum += i;
        }
    }
    return sum;
}