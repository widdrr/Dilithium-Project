CC=gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-loqs
SRC=src/server.c
OBJ=$(SRC:.c=.o)
TARGET=server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)