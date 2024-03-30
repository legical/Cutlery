/* debug complier : gcc - o multipath multipath.c - DPOUT */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SWAP(a, b)                                                             \
    {                                                                          \
        double temp = (a);                                                     \
        (a) = (b);                                                             \
        (b) = temp;                                                            \
    }

// 判断是否是闰年
int is_leap_year(int year) {
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
        return 1;
    else
        return 0;
}

int month_days(int month) {
    int sum = 0;
    switch (month) // 先计算某月以前月份的总天数
    {
    case 1:
        sum = 0;
        break;
    case 2:
        sum = 31;
        break;
    case 3:
        sum = 59;
        break;
    case 4:
        sum = 90;
        break;
    case 5:
        sum = 120;
        break;
    case 6:
        sum = 151;
        break;
    case 7:
        sum = 181;
        break;
    case 8:
        sum = 212;
        break;
    case 9:
        sum = 243;
        break;
    case 10:
        sum = 273;
        break;
    case 11:
        sum = 304;
        break;
    case 12:
        sum = 334;
        break;
    default:
        printf("month error!\n");
        break;
    }
    return sum;
}

int check_day(int month, int day) {
    if (day < 0) {
        day = 0 - day;
    } else if (day == 0) {
        day = 1;
    }
    if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 ||
        month == 10 || month == 12) {
        if (day > 31) {
            return day % 31;
        }
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        if (day > 30) {
            return day % 30;
        }
    } else if (month == 2) {
        if (day > 29) {
            return day % 29;
        }
    }
    return day;
}

#define MIN 20

/* Function Prototypes */
void initSeed(void);
void initialize(double **, int);
void calcSumAndMean(double[], int, double *, double *);
void calcVar(double[], int, double, double *);
double select_kth(double arr[], unsigned long k, unsigned long n);

int main(int argc, char *argv[]) {
    int year = 0, month = 1, day = 1, total_days = 0;
    // Check if there are enough command line arguments
    if (argc >= 2) {
        // Convert command line arguments to integers
        year = atoi(argv[1]);
        if (argc >= 3) {
            month = atoi(argv[2]);
            if (argc >= 4) {
                day = atoi(argv[3]);
            }
        }
    } else {
// If not enough command line arguments, read from stdin
#ifdef POUT
        printf("Enter three integers separated by spaces: ");
#endif
        char input[100];
        fgets(input, sizeof(input), stdin);
        sscanf(input, "%d %d %d", &year, &month, &day);
    }

    total_days = month_days(month);
    day = check_day(month, day);
    total_days += day;

    if (!is_leap_year(year)) {
        if (month == 2 && day == 29) {
            total_days--;
        }
    } else { // 如果是闰年且月份大于2，加一天
        if (month >= 3) {
            total_days++;
        }
    }
#ifdef POUT
    printf("Today is the %d day in this year.\n", total_days);
#endif
    double *ArrayA = NULL;
    initSeed();
    initialize(&ArrayA, total_days);

    if (day & 1) {
        double sum, mean, var;
        calcSumAndMean(ArrayA, total_days, &sum, &mean);
        calcVar(ArrayA, total_days, mean, &var);
#ifdef POUT
        printf("Sum: %f, Mean: %f, Var: %f\n", sum, mean, var);
#endif
    } else {
        double k_th = select_kth(ArrayA, day, total_days);
#ifdef POUT
        printf("The %d-th smallest element is %f\n", day, k_th);
#endif
    }
    free(ArrayA);

    return 0;
}

/* Function Definitions */

void initSeed() { srand((unsigned int)time(NULL)); }

void initialize(double **Array, int size) {
    if (size < MIN) {
        size = MIN;
    }
    *Array = (double *)malloc(size * sizeof(double));
    if (*Array == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    for (int i = 0; i < size; i++)
        (*Array)[i] = i + rand() / 8095.0;
}

void calcSumAndMean(double Array[], int size, double *Sum, double *Mean) {
    *Sum = 0;
    for (int i = 0; i < size; i++)
        *Sum += Array[i];
    *Mean = *Sum / size;
}

void calcVar(double Array[], int size, double Mean, double *Var) {
    double diffs = 0.0, cur_diff = 0.0;
    for (int i = 0; i < size; i++) {
        cur_diff = Array[i] - Mean;
        diffs += cur_diff * cur_diff;
    }

    *Var = diffs / size;
}

double select_kth(double arr[], unsigned long k, unsigned long n) {
    unsigned long i, ir, j, l, mid;
    double pivot;
    int flag, flag2;

    l = 0;
    ir = n - 1;
    flag = flag2 = 0;

    while (!flag) {
        if (ir <= l + 1) {
            if (ir == l + 1) {
                if (arr[ir] < arr[l]) {
                    SWAP(arr[l], arr[ir]);
                }
            }
            flag = 1;
        } else if (!flag) {
            mid = (l + ir) >> 1;
            SWAP(arr[mid], arr[l + 1]);
            if (arr[l + 1] > arr[ir]) {
                SWAP(arr[l + 1], arr[ir]);
            }
            if (arr[l] > arr[ir]) {
                SWAP(arr[l], arr[ir]);
            }
            if (arr[l + 1] > arr[l]) {
                SWAP(arr[l + 1], arr[l]);
            }
            i = l + 1;
            j = ir;
            pivot = arr[l];
            while (!flag2) {
                i++;
                while (arr[i] < pivot)
                    i++;
                j--;
                while (arr[j] > pivot)
                    j--;
                if (j < i)
                    flag2 = 1;
                if (!flag2) {
                    SWAP(arr[i], arr[j]);
                }
            }
            arr[l] = arr[j];
            arr[j] = pivot;
            if (j >= k)
                ir = j - 1;
            if (j <= k)
                l = i;
        }
    }
    return arr[k];
}