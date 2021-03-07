#include "dev.h"

double p = 0.51;

#define SIZE 10

int main(int argc, char *argv[]) {
	printf("hoi\n");
	double m1 = p;

	for (int i = 0; i <SIZE; i++) {
		printf("%lf %lf %lf %lf\n", m1, m1*p*(i+1), m1*p, m1*p*(i+1) - m1*p);
		m1 *= 1-p;
	}
}
