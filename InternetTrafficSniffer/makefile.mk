all: internetTrafficSniffer

internetTrafficSniffer: main.o packetHandler.o
	gcc $(CFLAGS) -o internetTrafficSniffer main.o packetHandler.o

main.o: main.c packetHandler.h
	gcc $(CFLAGS) -c main.c 

packetHandler.o: packetHandler.c packetHandler.h
	gcc $(CFLAGS) -c packetHandler.c

clean: 
	rm main.o packetHandler.o internetTrafficSniffer