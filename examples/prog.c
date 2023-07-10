#include <stdio.h>
#include <stdlib.h>
int main() {
	
	void * f = fopen("/dev/stdout", "w");
	if (f == NULL) {
		exit(EXIT_FAILURE);
	}
	fprintf(f, "Hello from executable!\n");
	if (fclose(f) != 0) {
		exit(EXIT_FAILURE);			
	}
}
