CC=gcc
CFLAGS=-Wall -Wextra -pedantic
SRC=src/client.c
OBJ=$(SRC:.c=.o)
TARGET=client

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)