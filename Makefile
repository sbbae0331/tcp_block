all: tcp_block 

tcp_block: main.o
	gcc -g -o tcp_block main.o -lpcap

main.o:
	gcc -g -c -o main.o main.c

clean:
	rm -f tcp_block
	rm -f *.o

