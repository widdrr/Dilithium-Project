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

bool run_performance_test(void) {
    // Create experiments directory if it doesn't exist
    system("mkdir -p /app/experiments");
    
    // Variables to track best performers
    double fastest_gen_time = -1;
    double fastest_sign_time = -1;
    double fastest_verify_time = -1;
    size_t shortest_pk = -1;
    size_t shortest_sk = -1;
    size_t shortest_sig = -1;
    char fastest_gen_alg[256] = "";
    char fastest_sign_alg[256] = "";
    char fastest_verify_alg[256] = "";
    char shortest_pk_alg[256] = "";
    char shortest_sk_alg[256] = "";
    char shortest_sig_alg[256] = "";

    // Test each algorithm
    for (size_t alg_idx = 0; alg_idx < OQS_SIG_algs_length; alg_idx++) {
        const char* alg_name = OQS_SIG_alg_identifier(alg_idx);
        if (!OQS_SIG_alg_is_enabled(alg_name)) {
            continue;
        }

        printf("\nTesting algorithm: %s\n", alg_name);
        
        char filename[256];
        snprintf(filename, sizeof(filename), "/app/experiments/%s_results.txt", alg_name);

        FILE *f = fopen(filename, "w");
        if (!f) {
            printf("Error: Could not create results file for %s\n", alg_name);
            continue;
        }

        fprintf(f, "Performance Test Results for %s\n", alg_name);
        fprintf(f, "Number of iterations: %d\n\n", NUM_TEST_ITERATIONS);

        OQS_SIG *sig = OQS_SIG_new(alg_name);
        if (!sig) {
            printf("Error: Could not initialize %s\n", alg_name);
            fclose(f);
            continue;
        }

        // Key generation timing
        double total_keygen_time = 0.0;
        printf("Testing key generation...\n");
        fprintf(f, "=== Key Generation ===\n");
        
        uint8_t *test_pk = malloc(sig->length_public_key);
        uint8_t *test_sk = malloc(sig->length_secret_key);
        
        for (int i = 0; i < NUM_TEST_ITERATIONS; i++) {
            double start_time = get_time_in_ms();
            OQS_SIG_keypair(sig, test_pk, test_sk);
            double end_time = get_time_in_ms();
            total_keygen_time += (end_time - start_time);
        }
        
        double avg_keygen_time = total_keygen_time / NUM_TEST_ITERATIONS;
        fprintf(f, "Average key generation time: %.2f ms\n", avg_keygen_time);
        fprintf(f, "Public key size: %zu bytes\n", sig->length_public_key);
        fprintf(f, "Secret key size: %zu bytes\n\n", sig->length_secret_key);

        // Update records for key generation
        if (fastest_gen_time < 0 || avg_keygen_time < fastest_gen_time) {
            fastest_gen_time = avg_keygen_time;
            strncpy(fastest_gen_alg, alg_name, sizeof(fastest_gen_alg)-1);
        }
        if (shortest_pk < 0 || sig->length_public_key < shortest_pk) {
            shortest_pk = sig->length_public_key;
            strncpy(shortest_pk_alg, alg_name, sizeof(shortest_pk_alg)-1);
        }
        if (shortest_sk < 0 || sig->length_secret_key < shortest_sk) {
            shortest_sk = sig->length_secret_key;
            strncpy(shortest_sk_alg, alg_name, sizeof(shortest_sk_alg)-1);
        }

        // Signing timing
        printf("Testing signing...\n");
        fprintf(f, "=== Signing ===\n");
        
        double total_sign_time = 0.0;
        size_t max_sig_size = 0;
        
        for (int i = 0; i < NUM_TEST_ITERATIONS; i++) {
            uint8_t *signature = malloc(sig->length_signature);
            size_t sig_actual_len;
            
            double start_time = get_time_in_ms();
            OQS_SIG_sign(sig, signature, &sig_actual_len, 
                         (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), 
                         test_sk);
            double end_time = get_time_in_ms();
            
            total_sign_time += (end_time - start_time);
            if (sig_actual_len > max_sig_size) max_sig_size = sig_actual_len;
            
            free(signature);
        }
        
        double avg_sign_time = total_sign_time / NUM_TEST_ITERATIONS;
        fprintf(f, "Average signing time: %.2f ms\n", avg_sign_time);
        fprintf(f, "Maximum signature size: %zu bytes\n\n", max_sig_size);

        // Update records for signing
        if (fastest_sign_time < 0 || avg_sign_time < fastest_sign_time) {
            fastest_sign_time = avg_sign_time;
            strncpy(fastest_sign_alg, alg_name, sizeof(fastest_sign_alg)-1);
        }
        if (shortest_sig < 0 || max_sig_size < shortest_sig) {
            shortest_sig = max_sig_size;
            strncpy(shortest_sig_alg, alg_name, sizeof(shortest_sig_alg)-1);
        }

        // Verification timing
        printf("Testing verification...\n");
        fprintf(f, "=== Verification ===\n");
        
        uint8_t *signature = malloc(sig->length_signature);
        size_t sig_actual_len;
        OQS_SIG_sign(sig, signature, &sig_actual_len, 
                     (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), 
                     test_sk);
        
        double total_verify_time = 0.0;
        
        for (int i = 0; i < NUM_TEST_ITERATIONS; i++) {
            double start_time = get_time_in_ms();
            OQS_SIG_verify(sig, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), 
                          signature, sig_actual_len, test_pk);
            double end_time = get_time_in_ms();
            total_verify_time += (end_time - start_time);
        }
        
        double avg_verify_time = total_verify_time / NUM_TEST_ITERATIONS;
        fprintf(f, "Average verification time: %.2f ms\n", avg_verify_time);

        // Update records for verification
        if (fastest_verify_time < 0 || avg_verify_time < fastest_verify_time) {
            fastest_verify_time = avg_verify_time;
            strncpy(fastest_verify_alg, alg_name, sizeof(fastest_verify_alg)-1);
        }

        // Cleanup
        free(signature);
        free(test_pk);
        free(test_sk);
        OQS_SIG_free(sig);
        fclose(f);
    }

    // Write summary file
    FILE *summary = fopen("/app/experiments/summary_results.txt", "w");
    if (!summary) {
        printf("Error: Could not create summary file\n");
        return false;
    }

    fprintf(summary, "=== Algorithm Performance Summary ===\n\n");
    fprintf(summary, "Fastest key generation: %s (%.2f ms)\n", fastest_gen_alg, fastest_gen_time);
    fprintf(summary, "Shortest public key: %s (%zu bytes)\n", shortest_pk_alg, shortest_pk);
    fprintf(summary, "Shortest secret key: %s (%zu bytes)\n", shortest_sk_alg, shortest_sk);
    fprintf(summary, "Fastest signing: %s (%.2f ms)\n", fastest_sign_alg, fastest_sign_time);
    fprintf(summary, "Shortest signature: %s (%zu bytes)\n", shortest_sig_alg, shortest_sig);
    fprintf(summary, "Fastest verification: %s (%.2f ms)\n", fastest_verify_alg, fastest_verify_time);
    
    fclose(summary);
    printf("\nTest results have been written to individual files in /app/experiments/\n");
    printf("Summary results have been written to: /app/experiments/summary_results.txt\n");
    
    return true;
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
    else if (strcmp(cmd, "test") == 0) {
        run_performance_test();
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
        printf("  test         - Run performance tests for all algorithms\n");
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