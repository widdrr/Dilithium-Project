FROM gcc:latest

WORKDIR /app
COPY . .
RUN make

# Use interactive shell as entrypoint
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["./client"]