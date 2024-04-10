#include <stdio.h>
#include <stdbool.h>

bool isPrime(int a) {
    if (a < 2)
        return 0;
    for (int i = 2; i * i <= a; ++i)
        if (a % i == 0)
            return 0;
    return 1;
}

int main() {
    // 输入一个数，判断是不是素数
    int n;
    scanf("%d", &n);
    if (isPrime(n))
        printf("YES\n");
    else
        printf("NO\n");
    return 0;
}