#ifndef UTILS_H
#define UTILS_H
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


#endif