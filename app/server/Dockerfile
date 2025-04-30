FROM gcc:latest

WORKDIR /app

# Install required packages
RUN apt-get update && \
    apt-get install -y \
    cmake \
    ninja-build \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    ldconfig

COPY src/ .

RUN gcc -o server server.c -loqs

EXPOSE 8080

CMD ["./server"]