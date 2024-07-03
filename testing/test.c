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
	int flag = 1;
	while (flag) {
		int choice = menu();
		switch (choice) {
			case 1: do_read(buf); break;
			case 2: do_write(buf); break;
			default: printf("INVALID\n"); flag = 0;
		}
	}
	puts("Confirm (Y/N)");
	char ch;
	scanf("%c", &ch);
	return 0;
}
