#include "utils.h"
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
    VoronoiDiagram diagram;

    if (num_points <= 10) {
        num_points = 10;
    } else if (num_points >= 50) {
        num_points = num_points % 50 + 10;
    }
    diagram.num_points = num_points;
    diagram.points = (Point *)malloc(num_points * sizeof(Point));
    diagram.connections = (int *)malloc(100 * 100 * sizeof(int));

    if (diagram.points == NULL || diagram.connections == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);
    }

    // Generate random points
    generate_points(diagram.points, num_points);

    // Populate connections
    for (int y = 0; y < 100; ++y) {
        for (int x = 0; x < 100; ++x) {
            int closest = closest_point(diagram.points, num_points, x, y);
            diagram.connections[y * 100 + x] = closest;
        }
    }

    return diagram;
}

// Function to free memory allocated for Voronoi diagram
void free_voronoi(VoronoiDiagram diagram) {
    free(diagram.points);
    free(diagram.connections);
}