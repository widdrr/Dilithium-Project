CC=gcc
CFLAGS=-Wall -Wextra -pedantic
LDFLAGS=-loqs
SRC=src/client.c
OBJ=$(SRC:.c=.o)
TARGET=client

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)