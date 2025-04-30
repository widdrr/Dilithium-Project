#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

// Global crypto state
uint8_t *public_key = NULL;
uint8_t *secret_key = NULL;
size_t sig_len;
size_t pk_len;
size_t sk_len;
size_t current_alg_index = 0;  // Default to first algorithm

void list_algorithms() {
    printf("\nAvailable signature algorithms:\n");
    for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
        const char* alg_name = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(alg_name)) {
            printf("[%zu] %s%s\n", i, alg_name, (i == current_alg_index) ? " (current)" : "");
        }
    }
}

bool set_algorithm(size_t index) {
    if (index >= OQS_SIG_algs_length) {
        printf("Invalid algorithm index\n");
        return false;
    }
    
    const char* alg_name = OQS_SIG_alg_identifier(index);
    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        printf("Algorithm %s is not enabled\n", alg_name);
        return false;
    }

    current_alg_index = index;
    printf("Algorithm set to: %s\n", alg_name);
    return true;
}

bool generate_keypair() {
    const char* alg_name = OQS_SIG_alg_identifier(current_alg_index);
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        printf("ERROR: OQS_SIG_new failed\n");
        return false;
    }

    pk_len = sig->length_public_key;
    sk_len = sig->length_secret_key;
    sig_len = sig->length_signature;

    public_key = malloc(pk_len);
    secret_key = malloc(sk_len);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("ERROR: OQS_SIG_keypair failed\n");
        OQS_SIG_free(sig);
        return false;
    }

    printf("\n=== Generated Keypair ===\n");
    printf("Algorithm: %s\n", alg_name);
    printf("Public key length: %zu bytes\n", pk_len);
    printf("Secret key length: %zu bytes\n", sk_len);
    printf("Public key (first 32 bytes): ");
    for (size_t i = 0; i < 32 && i < pk_len; i++) {
        printf("%02x", public_key[i]);
    }
    printf("...\n");

    OQS_SIG_free(sig);
    return true;
}

bool send_public_key(int sock) {
    if (public_key == NULL) {
        printf("No public key available\n");
        return false;
    }

    // Send algorithm index first
    uint32_t alg_idx = htonl(current_alg_index);
    if (send(sock, &alg_idx, sizeof(alg_idx), 0) < 0) {
        perror("Failed to send algorithm index");
        return false;
    }

    // Send public key length
    uint32_t len = htonl(pk_len);
    if (send(sock, &len, sizeof(len), 0) < 0) {
        perror("Failed to send public key length");
        return false;
    }

    // Send the public key
    if (send(sock, public_key, pk_len, 0) < 0) {
        perror("Failed to send public key");
        return false;
    }

    return true;
}

bool sign_message(const char *message, uint8_t **signature, size_t *actual_sig_len) {
    if (secret_key == NULL) {
        printf("No secret key available for signing\n");
        return false;
    }

    const char* alg_name = OQS_SIG_alg_identifier(current_alg_index);
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        printf("ERROR: OQS_SIG_new failed\n");
        return false;
    }

    *signature = malloc(sig_len);
    
    if (OQS_SIG_sign(sig, *signature, actual_sig_len, (uint8_t *)message, strlen(message), secret_key) != OQS_SUCCESS) {
        printf("ERROR: OQS_SIG_sign failed\n");
        free(*signature);
        OQS_SIG_free(sig);
        return false;
    }

    printf("\n=== Signature Generated ===\n");
    printf("Algorithm: %s\n", alg_name);
    printf("Message: '%s'\n", message);
    printf("Signature length: %zu bytes\n", *actual_sig_len);
    printf("Signature (first 32 bytes): ");
    for (size_t i = 0; i < 32 && i < *actual_sig_len; i++) {
        printf("%02x", (*signature)[i]);
    }
    printf("...\n");

    OQS_SIG_free(sig);
    return true;
}

bool send_payload(int sock, const char *message, const uint8_t *signature, size_t signature_len) {
    size_t message_len = strlen(message);
    size_t total_len = message_len + signature_len;
    uint8_t *combined_buffer = malloc(total_len);
    
    // Copy message and signature into the combined buffer
    memcpy(combined_buffer, message, message_len);
    memcpy(combined_buffer + message_len, signature, signature_len);

    // Send total length
    uint32_t len_network = htonl(total_len);
    if (send(sock, &len_network, sizeof(len_network), 0) < 0) {
        perror("Failed to send total length");
        free(combined_buffer);
        return false;
    }

    // Send combined message and signature
    if (send(sock, combined_buffer, total_len, 0) < 0) {
        perror("Failed to send message and signature");
        free(combined_buffer);
        return false;
    }

    free(combined_buffer);
    return true;
}

bool sign_and_send_message(int sock, const char *message) {
    uint8_t *signature;
    size_t signature_len;

    if (!sign_message(message, &signature, &signature_len)) {
        return false;
    }

    bool result = send_payload(sock, message, signature, signature_len);
    free(signature);
    return result;
}

bool send_fake_signed_message(int sock, const char *message) {
    uint8_t *signature;
    size_t signature_len;

    if (!sign_message(message, &signature, &signature_len)) {
        return false;
    }

    // Corrupt the signature by flipping some bits
    for(size_t i = 0; i < signature_len && i < 8; i++) {
        signature[i] ^= 0xFF;
    }

    bool result = send_payload(sock, message, signature, signature_len);
    free(signature);
    return result;
}

void cleanup_crypto() {
    if (public_key) {
        free(public_key);
        public_key = NULL;
    }
    if (secret_key) {
        free(secret_key);
        secret_key = NULL;
    }
}

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
        if (*sock != -1) {
            if (!generate_keypair()) {
                printf("Failed to generate keypair\n");
                close(*sock);
                *sock = -1;
                return;
            }
            if (!send_public_key(*sock)) {
                printf("Failed to send public key\n");
                close(*sock);
                *sock = -1;
                return;
            }
            printf("Connected and key exchange completed\n");
        }
    }
    else if (strcmp(cmd, "disconnect") == 0) {
        if (*sock == -1) {
            printf("Not connected\n");
            return;
        }
        close(*sock);
        *sock = -1;
        cleanup_crypto();
        printf("Disconnected from server\n");
    }
    else if (strncmp(cmd, "msg ", 4) == 0) {
        if (*sock == -1) {
            printf("Not connected to server\n");
            return;
        }
        
        char* message = cmd + 4;  // Skip "msg " prefix

        bool success = sign_and_send_message(*sock, message);
        if (!success) {
            printf("Failed to send signed message\n");
            return;
        }
        printf("Signed message sent: %s\n", message);

        int bytes_received = recv(*sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server response: %s\n", buffer);
        }
    }
    else if (strncmp(cmd, "fake ", 5) == 0) {
        if (*sock == -1) {
            printf("Not connected to server\n");
            return;
        }
        
        char* message = cmd + 5;  // Skip "fake " prefix

        bool success = send_fake_signed_message(*sock, message);
        if (!success) {
            printf("Failed to send fake signed message\n");
            return;
        }
        printf("Fake signed message sent: %s\n", message);

        int bytes_received = recv(*sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server response: %s\n", buffer);
        }
    }
    else if (strcmp(cmd, "algorithms") == 0 || strcmp(cmd, "alg") == 0) {
        list_algorithms();
    }
    else if (strncmp(cmd, "setalg ", 7) == 0) {
        if (*sock != -1) {
            printf("Cannot change algorithm while connected\n");
            return;
        }
        
        char* index_str = cmd + 7;  // Skip "setalg " prefix
        char* endptr;
        size_t index = strtoul(index_str, &endptr, 10);
        
        if (*endptr != '\0' && !isspace(*endptr)) {
            printf("Invalid algorithm index\n");
            return;
        }

        set_algorithm(index);
    }
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        if (*sock != -1) {
            close(*sock);
        }
        cleanup_crypto();
        *running = false;
    }
    else {
        printf("Available commands:\n");
        printf("  connect      - Connect to server and perform key exchange\n");
        printf("  disconnect   - Disconnect from server\n");
        printf("  algorithms   - List available signature algorithms\n");
        printf("  setalg <id>  - Set signature algorithm by index (when not connected)\n");
        printf("  msg <text>   - Send signed message to server\n");
        printf("  fake <text>  - Send message with invalid signature\n");
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