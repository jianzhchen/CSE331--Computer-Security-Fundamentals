#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {

	char target[]="/bin/sh";
	char *p = (char *) 0xb7ec2990;
	while (memcmp(++p, target, sizeof target)){

	}
	printf("%s\n", p);
	printf("%p\n", p);
	
	return 0;
}
