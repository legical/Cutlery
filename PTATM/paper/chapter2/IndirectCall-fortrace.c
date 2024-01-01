void foo(void (*func)()) {
    return func();
}

void func() {

}

int main() {
    foo(func);
    return 0;
}
