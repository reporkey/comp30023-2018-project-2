CC=gcc
CFLAGS=-I. -lssl -lcrypto -Wall
TARGET = certcheck

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c $(CFLAGS)

clean:
	rm $(TARGET)
