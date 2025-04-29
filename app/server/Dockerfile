FROM gcc:latest

WORKDIR /app

COPY src/ .

RUN gcc -o server server.c

# Expose the port
EXPOSE 8080

CMD ["./server"]