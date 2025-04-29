#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define CMD_SIZE 1024

int connect_to_server() {
    int sock;
    struct sockaddr_in server_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "172.20.0.2", &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    printf("Connected to server\n");
    return sock;
}

void process_command(int *sock, char* cmd, bool *running) {
    char buffer[BUFFER_SIZE];
    
    if (strcmp(cmd, "connect") == 0) {
        if (*sock != -1) {
            printf("Already connected\n");
            return;
        }
        *sock = connect_to_server();
    }
    else if (strcmp(cmd, "disconnect") == 0) {
        if (*sock == -1) {
            printf("Not connected\n");
            return;
        }
        close(*sock);
        *sock = -1;
        printf("Disconnected from server\n");
    }
    else if (strncmp(cmd, "msg ", 4) == 0) {
        if (*sock == -1) {
            printf("Not connected to server\n");
            return;
        }
        
        char* message = cmd + 4;  // Skip "msg " prefix
        if (send(*sock, message, strlen(message), 0) < 0) {
            perror("Send failed");
            return;
        }
        printf("Message sent: %s\n", message);

        int bytes_received = recv(*sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server response: %s\n", buffer);
        }
    }
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        if (*sock != -1) {
            close(*sock);
        }
        *running = false;
    }
    else {
        printf("Available commands:\n");
        printf("  connect      - Connect to server\n");
        printf("  disconnect   - Disconnect from server\n");
        printf("  msg <text>   - Send message to server\n");
        printf("  exit/quit    - Close the client\n");
    }
}

int main() {
    char cmd_buffer[CMD_SIZE];
    int sock = -1;
    bool running = true;

    printf("Client started. Run 'docker attach dilithium-client' in a separate terminal.\n");
    printf("Type 'help' for available commands.\n");

    while (running) {
        printf("> ");
        fflush(stdout);

        if (fgets(cmd_buffer, CMD_SIZE, stdin) == NULL) {
            break;
        }

        // Remove trailing newline
        size_t len = strlen(cmd_buffer);
        if (len > 0 && cmd_buffer[len-1] == '\n') {
            cmd_buffer[len-1] = '\0';
        }

        process_command(&sock, cmd_buffer, &running);
    }

    if (sock != -1) {
        close(sock);
    }
    printf("Client terminated\n");
    return 0;
}