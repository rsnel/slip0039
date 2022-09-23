#include <math.h>
#include <assert.h>
#include "dev.h"
#include <sys/random.h>

double p = 0.78;

#define SIZE 1000000
#define MAX 10

double encodable_at(int k) {
	assert(k >= 0);
	return pow(1 - p, k);
}
	
double not_encodable_at(int k) {
	return 1. - encodable_at(k);
}

double not_encodable_at_1_to_k(int k) {
	assert(k >= 0);
	double ret = 1;
	for (int i = 1; i <= k; i++) {
		ret *= not_encodable_at(i);
	}
	return ret;
}

double first_encodable_at(int k) {
	assert(k >= 0);
	return  not_encodable_at_1_to_k(k-1)*encodable_at(k);
}

double encoded_at(int k) {
	return encodable_at(k)*p;
}

double grd() {
	uint64_t data;
	getrandom(&data, sizeof(data), 0);
	return (double)data/(double)UINT64_MAX;
}

int sim_encoded_at() {
	double p;
	double cumulative[MAX] = { };
	cumulative[0] = 0; //encoded_at(0);
	for (int i = 1; i < MAX; i++) {
		p = encodable_at(i);
		if (grd() < p) {
			cumulative[i] = cumulative[i-1] + encoded_at(i);
	//		printf("encodable at %i\n", i);
		} else {
			cumulative[i] = cumulative[i-1];
	//		printf("not encodable at %i\n", i);
		}
	}
	p = grd();
	int encoded_at = -1;
	for (int i = 0; i < MAX; i++) {
		cumulative[i] /= cumulative[MAX-1];
	//	printf("cumulative[%d] = %f\n", i, cumulative[i]);
		if (p < cumulative[i] && encoded_at == -1) encoded_at = i;
	}
	if (encoded_at == -1) encoded_at = 0;
	return encoded_at;
}

int main(int argc, char *argv[]) {
	int count[MAX] = { };
	int i = 1;
	double only_encodable_at_0 = 1, delta;

	goto start;

	do {
		only_encodable_at_0 -= delta;
start:
		//printf("only_encodable_at_0=%f\n", only_encodable_at_0);
		delta = first_encodable_at(i++);
	} while (only_encodable_at_0 != only_encodable_at_0 - delta);

	printf("only_encodable_at_0=%f\n", only_encodable_at_0);

	//exit(0);
	for (int i = 0; i < SIZE; i++) {
		count[sim_encoded_at()]++;
	}

	for (int i = 0; i < MAX; i++) {
		printf("%d %f %f\n", i, encoded_at(i), (double)count[i]/(double)SIZE);
	}
}
