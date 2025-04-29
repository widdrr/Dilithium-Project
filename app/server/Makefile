CC=gcc
CFLAGS=-Wall -Wextra -g
SRC=src/server.c
OBJ=$(SRC:.c=.o)
TARGET=server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)