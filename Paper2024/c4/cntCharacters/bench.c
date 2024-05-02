#include <stdio.h>

// 检查字符是否为元音字母
int isVowel(char c) {
    switch (c) {
        case 'A':
        case 'E':
        case 'I':
        case 'O':
        case 'U':
        case 'a':
        case 'e':
        case 'i':
        case 'o':
        case 'u':
            return 1;
        default:
            return 0;
    }
}

void countCharacters(const char *str, int *letterCount, int *digitCount, int *spaceCount, int *vowelCount, int *otherCount, int *upperCaseCount, int *lowerCaseCount) {
    *letterCount = 0;
    *digitCount = 0;
    *spaceCount = 0;
    *vowelCount = 0;
    *otherCount = 0;
    *upperCaseCount = 0;
    *lowerCaseCount = 0;

    while (*str) {
        if (*str >= 'A' && *str <= 'Z') {
            (*upperCaseCount)++;
            if (*str == 'A' || *str == 'E' || *str == 'I' || *str == 'O' || *str == 'U') {
                (*vowelCount)++;
            }
        } else if (*str >= 'a' && *str <= 'z') {
            (*lowerCaseCount)++;
            if (*str == 'a' || *str == 'e' || *str == 'i' || *str == 'o' || *str == 'u') {
                (*vowelCount)++;
            }
        } else if (*str >= '0' && *str <= '9') {
            (*digitCount)++;
        } else if (*str == ' ') {
            (*spaceCount)++;
        } else {
            (*otherCount)++;
        }
        str++;
    }
    (*letterCount) = (*upperCaseCount) + (*lowerCaseCount);
}

void reverseVowels(char *str, int *upperCaseCount, int *lowerCaseCount) {
    int i = -1;
    while (str[++i]) {        
        if (str[i] >= 'a' && str[i] <= 'z') {
            if (isVowel(str[i])) {
                str[i] = str[i] - 'a' + 'A';
                (*upperCaseCount)++;
                (*lowerCaseCount)--;
            }            
        } else if (str[i] >= 'A' && str[i] <= 'Z') {
            if (isVowel(str[i])) {
                str[i] = str[i] - 'A' + 'a';
                (*lowerCaseCount)++;
                (*upperCaseCount)--;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    char str[100]={0};
    int letterCount, digitCount, spaceCount, vowelCount, otherCount, upperCaseCount, lowerCaseCount;

    fgets(str, sizeof(str), stdin);
    // gets(str); //存在栈溢出漏洞

    countCharacters(str, &letterCount, &digitCount, &spaceCount, &vowelCount, &otherCount, &upperCaseCount, &lowerCaseCount);

    reverseVowels(str, &upperCaseCount, &lowerCaseCount);

    if (str[0] == 'A') printf("vowelCount: %d\n", vowelCount);
    else if (str[0] == 'L') printf("letterCount: %d\n", letterCount);
    else if (str[0] == 'd') printf("digitCount: %d\n", digitCount);
    else if (str[0] == 'S') printf("spaceCount: %d\n", spaceCount);
    else if (str[0] == 'C') printf("lowerCaseCount: %d\n", lowerCaseCount);
    else if (str[0] == 'u') printf("upperCaseCount: %d\n", upperCaseCount);
    else printf("otherCount: %d\n", otherCount);
    
    return 0;
}
