#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void checkCharacters(const char *str) {
    // 判断字符串是否为空或长度是否为0
    if (strlen(str) == 0) {
        printf("输入的字符串为空\n");
    } else {
        // 判断第一个字符的类型并打印对应输出
        if (*str >= 'A' && *str <= 'Z') {
            printf("第一个字符是大写英文字母：%c\n", *str);
        } else if (*str >= 'a' && *str <= 'z') {
            printf("第一个字符是小写英文字母：%c\n", *str);
        } else if (*str >= '0' && *str <= '9') {
            printf("第一个字符是数字：%c\n", *str);
        } else {
            printf("第一个字符是其他字符：%c\n", *str);
        }
    }    
}

void checkStrLen(const char *str) {
    int len = strlen(str);

    if (len & 1) {
        printf("输入的字符串长度为奇数\n");
    } else {
        printf("输入的字符串长度为偶数\n");
    }
}

void checkVowel(const char *str) {
    if (strlen(str) < 2) {
        printf("输入的字符串不合法\n");
    } else {
        // 判断第二个字符是否为元音字母并打印对应输出
        if (str[1] == 'a') {
            printf("第二个字符是元音字母a\n");
        } else if (str[1] == 'e') {
            printf("第二个字符是元音字母e\n");
        } else if (str[1] == 'i') {
            printf("第二个字符是元音字母i\n");
        } else if (str[1] == 'o') {
            printf("第二个字符是元音字母o\n");
        } else if (str[1] == 'u') {
            printf("第二个字符是元音字母u\n");
        } else {
            printf("第二个字符不是元音字母\n");
        }
    }
}

int main(int argc, char* argv[]) {
    char str[100]={0};

    fgets(str, sizeof(str), stdin);
    // gets(str); //存在栈溢出漏洞

    checkCharacters(str);

    checkStrLen(str);

    checkVowel(str);
    
    return 0;
}
