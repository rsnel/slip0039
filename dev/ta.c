#include <stdio.h>
#include <stdlib.h>
#include "dev.h"

int main(int argc, char *argv[]) {
	char a = 44;
	printf("%02x %02x\n", a, (char)-a);
	printf("%d\n", cthelp_eq(2, 3));
	printf("%d\n", cthelp_eq(-2, -2));
	exit(0);
}
