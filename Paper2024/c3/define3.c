int add1(int a) {
    a += 1;
    return a;
}

int add2(int a) {
    a += 2;
    return a;
}

int main() {
    int a = 5;
    add1(a);
    add2(a);
    return 0;
}