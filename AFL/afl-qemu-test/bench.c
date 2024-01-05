#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        if (str[i] == 'a' || str[i] == 'A' || str[i] == 'e' || str[i] == 'E' || str[i] == 'i' || str[i] == 'I' || str[i] == 'o' || str[i] == 'O' || str[i] == 'u' || str[i] == 'U') {
            if (str[i] >= 'a' && str[i] <= 'z') {
                str[i] = str[i] - 'a' + 'A';
                (*upperCaseCount)++;
                (*lowerCaseCount)--;
            } else if (str[i] >= 'A' && str[i] <= 'Z') {
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


    return 0;
}
