#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

bool receive_public_key(int socket, ClientInfo *client) {
    // Receive algorithm index first
    uint32_t alg_idx;
    if (recv(socket, &alg_idx, sizeof(alg_idx), 0) <= 0) {
        return false;
    }
    client->alg_index = ntohl(alg_idx);

    // Receive public key length
    uint32_t len;
    if (recv(socket, &len, sizeof(len), 0) <= 0) {
        return false;
    }
    len = ntohl(len);

    // Allocate memory for public key
    client->public_key = malloc(len);
    client->pk_len = len;
    
    // Get signature length from the algorithm
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_identifier(client->alg_index));
    if (sig == NULL) {
        free(client->public_key);
        return false;
    }
    client->sig_len = sig->length_signature;
    OQS_SIG_free(sig);

    // Receive public key
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received = recv(socket, client->public_key + total_received, 
                              len - total_received, 0);
        if (received <= 0) {
            free(client->public_key);
            return false;
        }
        total_received += received;
    }

    printf("\n=== Received Client Public Key ===\n");
    printf("Algorithm: %s\n", OQS_SIG_alg_identifier(client->alg_index));
    printf("Public key length: %zu bytes\n", client->pk_len);
    printf("Public key (first 32 bytes): ");
    for (size_t i = 0; i < 32 && i < client->pk_len; i++) {
        printf("%02x", client->public_key[i]);
    }
    printf("...\n");

    return true;
}

bool verify_message(const uint8_t *public_key, size_t pk_len,
                   const uint8_t *message, size_t msg_len,
                   const uint8_t *signature, size_t sig_len,
                   size_t alg_index) {
    const char* alg_name = OQS_SIG_alg_identifier(alg_index);
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        return false;
    }

    printf("\n=== Verifying Signature ===\n");
    printf("Algorithm: %s\n", alg_name);
    printf("Message: '%.*s'\n", (int)msg_len, message);
    printf("Signature length: %zu bytes\n", sig_len);
    printf("Signature (first 32 bytes): ");
    for (size_t i = 0; i < 32 && i < sig_len; i++) {
        printf("%02x", signature[i]);
    }
    printf("...\n");

    bool result = (OQS_SIG_verify(sig, message, msg_len, signature, sig_len, 
                                 public_key) == OQS_SUCCESS);
    
    printf("Verification result: %s\n", result ? "SUCCESS" : "FAILED");
    
    OQS_SIG_free(sig);
    return result;
}

bool handle_client_message(int socket, ClientInfo *client) {
    // Receive total length
    uint32_t total_len;
    if (recv(socket, &total_len, sizeof(total_len), 0) <= 0) {
        return false;
    }
    total_len = ntohl(total_len);

    // Allocate buffer for entire payload
    uint8_t *payload = malloc(total_len);
    size_t total_received = 0;
    while (total_received < total_len) {
        ssize_t received = recv(socket, payload + total_received, 
                              total_len - total_received, 0);
        if (received <= 0) {
            free(payload);
            return false;
        }
        total_received += received;
    }

    size_t msg_len = total_len - client->sig_len;
    uint8_t *message = payload;
    uint8_t *signature = payload + msg_len;

    // Verify signature
    bool is_valid = verify_message(client->public_key, client->pk_len,
        message, msg_len,
        signature, client->sig_len, client->alg_index);

    // Null terminate message for printing
    message[msg_len] = '\0';
    printf("Received message: %s\n", (char *)message);
    printf("Signature verification: %s\n", is_valid ? "SUCCESS" : "FAILED");

    // Send response to client
    const char *response = is_valid ? "Message verified successfully" : 
                "Signature verification failed";
    send(socket, response, strlen(response), 0);

    free(payload);
    return true;
}

void cleanup_client(ClientInfo *client) {
    if (client->public_key) {
        free(client->public_key);
        client->public_key = NULL;
    }
}

int main() {
    setbuf(stdout, NULL);  // Disable buffering on stdout

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    ClientInfo client = {NULL, 0};

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", PORT);

    while (1) {
        // Accept incoming connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                               (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        printf("New client connected\n");

        // Receive client's public key
        if (!receive_public_key(new_socket, &client)) {
            printf("Failed to receive public key\n");
            close(new_socket);
            cleanup_client(&client);
            continue;
        }

        printf("Received client's public key\n");

        // Handle messages from client
        while (1) {
            if (!handle_client_message(new_socket, &client)) {
                printf("Client disconnected\n");
                break;
            }
        }

        cleanup_client(&client);
        close(new_socket);
    }

    close(server_fd);
    return 0;
}