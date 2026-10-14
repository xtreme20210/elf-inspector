CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -g
TARGET = elfinspect

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(FLAGS) main.c -o $(TARGET)

clean: 
	rm -f $(TARGET)

.PHONY: all clean