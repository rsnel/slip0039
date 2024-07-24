#include <stdio.h>
#include <stdlib.h>
#include <math.h>

const double p = 0.75, q = 1 - p;
int limit = 8;

int main(int argc, char *argv[]) {
	for (int i = 0; i < limit; i++) {
		printf("%d %lf %lf\n", i, p*p*(i+1)*pow(q, i), p*pow(q,i));
	}
	exit(0);
}

