int increase(int a) {
    return a;
}

int main() {
    int a = 0, b = 1;
    a = increase(a);
    a += b;
    b = increase(a);
    return 0;
}