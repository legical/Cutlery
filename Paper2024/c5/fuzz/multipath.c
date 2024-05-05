/* debug complier : gcc -o multi multipath.c -DPOUT */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define SWAP(a, b)                                                             \
    {                                                                          \
        double temp = (a);                                                     \
        (a) = (b);                                                             \
        (b) = temp;                                                            \
    }

#define MIN 20

typedef struct {
    int x, y;
} Point;

typedef struct {
    Point *points;
    int *connections;
    int num_points;
} VoronoiDiagram;

/* Function Prototypes */
void initSeed(void);
void initialize(double **, int);
void calcSumAndMean(double[], int, double *, double *);
void calcVar(double[], int, double, double *);
double select_kth(double arr[], unsigned long k, unsigned long n);
void generate_points(Point points[], int);
int closest_point(Point points[], int, int, int);
VoronoiDiagram generate_voronoi(int);
void free_voronoi(VoronoiDiagram diagram);


// 判断是否是闰年
int is_leap_year(int year) {
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
        return 1;
    else
        return 0;
}

int month_days(int month) {
    int sum = 0;
    VoronoiDiagram diagram = {NULL, NULL, 0};
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
    VoronoiDiagram diagram = {NULL, NULL, 0};
    if (day < 0) {
        day = 0 - day;
    } else if (day == 0) {
        day = 1;
    }
    if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 ||
        month == 10 || month == 12) {
        if (day > 31) {
            day %= 31;            
        }
        diagram = generate_voronoi(day);
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        if (day > 30) {
            day %= 30;
        }
        diagram = generate_voronoi(day);
    } else if (month == 2) {
        if (day > 29) {
            day %= 29;
        }
        diagram = generate_voronoi(day);
    }
    free_voronoi(diagram);
    return day;
}

int main() {
    int year = 0, month = 1, day = 1, total_days = 0;
    // Check if there are enough command line arguments
//     if (argc >= 2) {
//         // Convert command line arguments to integers
//         year = atoi(argv[1]);
//         if (argc >= 3) {
//             month = atoi(argv[2]);
//             if (argc >= 4) {
//                 day = atoi(argv[3]);
//             }
//         }
//     } else {
// // If not enough command line arguments, read from stdin
// #ifdef POUT
//         printf("Enter three integers separated by spaces: ");
// #endif
        char input[100];
        fgets(input, sizeof(input), stdin);
        sscanf(input, "%d %d %d", &year, &month, &day);
        // scanf("%d %d %d", &year, &month, &day);
    // }
    if (month < 1) month = 1;
    if (month > 12) month = 12;
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

/* Function Definitions */

void initSeed() { srand((unsigned int)time(NULL)); }

void initialize(double **Array, int size) {
    initSeed();
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

// Generate random points
void generate_points(Point points[], int num_points) {
    srand(time(NULL));
    for (int i = 0; i < num_points; ++i) {
        points[i].x = rand() % 100;
        points[i].y = rand() % 100;
    }
}

// Find the closest point to a given pixel
int closest_point(Point points[], int num_points, int x, int y) {
    int min_dist = 10000; // large enough initial distance
    int index = -1;
    for (int i = 0; i < num_points; ++i) {
        int dist = (points[i].x - x) * (points[i].x - x) +
                   (points[i].y - y) * (points[i].y - y);
        if (dist < min_dist) {
            min_dist = dist;
            index = i;
        }
    }
    return index;
}

// Function to generate Voronoi diagram
VoronoiDiagram generate_voronoi(int num_points) {
    VoronoiDiagram diagram = {NULL, NULL, 0};

    if (num_points <= 10) {
        num_points = 10;
    } else if (num_points >= 50) {
        num_points = num_points % 50 + 10;
    }
    diagram.num_points = num_points;
    // diagram.points = (Point *)malloc(num_points * sizeof(Point));
    // diagram.connections = (int *)malloc(100 * 100 * sizeof(int));

    // if (diagram.points == NULL || diagram.connections == NULL) {
    //     printf("Memory allocation failed.\n");
    //     exit(1);
    // }

    // // Generate random points
    // generate_points(diagram.points, num_points);

    // // Populate connections
    // for (int y = 0; y < 100; ++y) {
    //     for (int x = 0; x < 100; ++x) {
    //         int closest = closest_point(diagram.points, num_points, x, y);
    //         diagram.connections[y * 100 + x] = closest;
    //     }
    // }

    return diagram;
}

// Function to free memory allocated for Voronoi diagram
void free_voronoi(VoronoiDiagram diagram) {
    if (diagram.points && diagram.connections) {
        free(diagram.points);
        free(diagram.connections);
    }
}