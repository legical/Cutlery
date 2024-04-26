/* debug complier : gcc -o multi multipath.c -DPOUT */

#include "utils.h"

// 判断是否是闰年
int is_leap_year(int year) {
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
        return 1;
    else
        return 0;
}

int month_days(int month) {
    int sum = 0;
    VoronoiDiagram diagram;
    switch (month) // 先计算某月以前月份的总天数
    {
    case 1:
        sum = 0;
        diagram = generate_voronoi(sum);
        
        break;
    case 2:
        sum = 31;
        diagram = generate_voronoi(sum);
        
        break;
    case 3:
        sum = 59;
        diagram = generate_voronoi(sum);
        
        break;
    case 4:
        sum = 90;
        diagram = generate_voronoi(sum);
        
        break;
    case 5:
        sum = 120;
        diagram = generate_voronoi(sum);
        
        break;
    case 6:
        sum = 151;
        diagram = generate_voronoi(sum);
        
        break;
    case 7:
        sum = 181;
        diagram = generate_voronoi(sum);
        
        break;
    case 8:
        sum = 212;
        diagram = generate_voronoi(sum);
        
        break;
    case 9:
        sum = 243;
        diagram = generate_voronoi(sum);
        
        break;
    case 10:
        sum = 273;
        diagram = generate_voronoi(sum);
        
        break;
    case 11:
        sum = 304;
        diagram = generate_voronoi(sum);
        
        break;
    case 12:
        sum = 334;
        diagram = generate_voronoi(sum);
        
        break;
    default:
        diagram = generate_voronoi(sum);
        printf("month error!\n");
        break;
    }
    free_voronoi(diagram);
    return sum;
}

int check_day(int month, int day) {
    VoronoiDiagram diagram;
    if (day < 0) {
        day = 0 - day;
    } else if (day == 0) {
        day = 1;
    }
    if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 ||
        month == 10 || month == 12) {
        if (day > 31) {
            day %= 31;
            diagram = generate_voronoi(day);
            
        }
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        if (day > 30) {
            day %= 30;
            diagram = generate_voronoi(day);
            
        }
    } else if (month == 2) {
        if (day > 29) {
            day %= 29;
            diagram = generate_voronoi(day);
            
        }
    }
    return day;
}

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
// #ifdef POUT
    printf("Today is the %d day in this year.\n", total_days);
// #endif
    double *ArrayA = NULL;
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

