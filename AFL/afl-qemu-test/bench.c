#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int function1(char* str) {
    int length = strlen(str);
    
    if (length < 5) {
        return length - 5;
    } else if (length == 5) {
        return 2;
    } else if (length == 6) {
        return 3;
    } else if (length == 7) {
        return 4;
    } else {
        return length;
    }
}

int case1(int a, int b) {
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

int function2(char* str) {
    int count = 0;
    int i;
    int length = strlen(str);

    for (i = 0; i < length; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            count++;
        }
    }

    if (count == 0) {
        return 0;
    } else if (count == 1) {
        return 2;
    } else if (count == 2) {
        return 3;
    } else if (count == 3) {
        return 4;
    } else {
        return count;
    }
}

int function3(char* str) {
    int length = strlen(str);
    int i;
    int sum = 0;

    for (i = 0; i < length; i++) {
        sum += str[i] - '0';
    }

    if (sum % 2 == 0) {
        return 1;
    } else {
        return sum;
    }
}

int case3(int c) {
	int sum = 0;
	for (int i=0; i<100*c; ++i) {
		if (i % 2) {
			sum += 2*i;
		} else {
			sum = sum + i;
		}
	}
	return sum;
}

int vuln(char *str, int a, int b, int c)
 {
    //  int len = strlen(str);
     if(str[0] == 'A' && a == 10)
     {
        abort();
         //如果输入的字符串的首字符为A并且长度为10，则异常退出
     }
     else if(b == 2 && c == 1)
     {
        abort();
         //如果输入的字符串的有2个大写字母且长度为减去0的和为偶数，则异常退出
     }
     else str[0] += a;
     return 0;
 }

int main(int argc, char* argv[]) {
    char str[100]={0};
    gets(str);//存在栈溢出漏洞

    int a = function1(str);

    int b = function2(str);

    case1(a, b);

    int c = function3(str);

    case3(c);
    vuln(str, a, b, c);

    return 0;
}
