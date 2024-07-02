#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


void do_read(char *buf) {
	gets(buf);
	return;
}


void do_write(char *buf) {
	printf(buf);
	return;
}


int menu() {
	printf("1: Read\n2: Write\nEnter your choice (1/2) : ");
	char cmd[20];
	read(0, cmd, 19);
	return atoi(cmd);
}


int main() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	char buf[0x100];
	while (1) {
		int choice = menu();
		switch (choice) {
			case 1: do_read(buf); break;
			case 2: do_write(buf); break;
			default: printf("INVALID\n"); return 0;
		}
	}
	return 0;
}
