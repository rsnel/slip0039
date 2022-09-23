#include <math.h>
#include <assert.h>
#include "dev.h"

//double p = 0.99;
double p = 0.78;
//double p = 0.5;

#define SIZE 20

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
	return not_encodable_at_1_to_k(k-1)*encodable_at(k);
}

double encoded_at(int k) {
	return encodable_at(k)*p;
}

int main(int argc, char *argv[]) {
	double summand = 0, delta;
	int i = 1;

	while ((delta = first_encodable_at(i)) > 0.0000001) {
	//while ((delta = not_encodable_at_1_to_k(i-1)*encodable_at(i)) > 0.0000001) {
		i++;
		summand += delta;
	}
	printf("summand: %lf\n", summand);

	double placed[i];
	printf("   ");
	for (int j = 0; j < i; j++) {
		printf("%2d       ", j);
		placed[j] = 0;
	}
	printf("\n");
	printf("   ");
	for (int j = 0; j < i; j++) {
		printf("%lf ", encoded_at(j));
	}
	printf("\n");

	for (int k = 1; k < i - 1; k++) {
		printf("%2d ", k);
		for (int j = 0; j < k + 1; j++) {
			printf("_.______ ");
		}
		for (int j = k + 1; j < i; j++) {
			printf("%lf ", encoded_at(j)*encodable_at(k));
		}
		printf("\n");
	}

	for (int k = 0; k < i; k++) {
		printf("%2d ", k);
		if (k == 0) {
			printf("%lf ", 1 - summand);
			for (int j = 1; j < i; j++) printf("_.______ ");
		} else {
			double sum = 0;
			for (int j = k + 1; j < i; j++) {
				sum += encoded_at(k)*encodable_at(j);
				placed[j] += encoded_at(k)*encodable_at(j);
			}
			sum += encoded_at(k) - placed[k];
			printf("%lf ", first_encodable_at(k) - sum);
			for (int j = 1; j < k; j++) printf("_.______ ");
			printf("%lf ", encoded_at(k) - placed[k]);
			for (int j = k + 1; j < i; j++) printf("%lf ", encoded_at(k)*encodable_at(j));
		}
		printf("\n");
	}

}
