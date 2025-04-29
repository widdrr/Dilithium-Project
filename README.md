# Readme

## Overview

This project implements a minimal client-server architecture using C. The client connects to the server to send and receive messages. Both the client and server are containerized using Docker, allowing for easy deployment and management.

## Project Structure

```
app
├── client
│   ├── src
│   │   └── client.c
│   ├── Dockerfile
│   └── Makefile
├── server
│   ├── src
│   │   └── server.c
│   ├── Dockerfile
│   └── Makefile
├── docker-compose.yml
└── README.md
```

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd app
   ```

2. **Build the Docker Images**
   ```bash
   docker compose build
   ```

3. **Run the Application**
   ```bash
   docker compose up
   ```

## Usage

- The server will start and listen for incoming connections.
- The client can be run to connect to the server and exchange messages.

## Disclaimer
Most of the project setup and container infrastructure was done with the help of AI