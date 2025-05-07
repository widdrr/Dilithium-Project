#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <sys/time.h>

// Constants
#define PORT 8080
#define BUFFER_SIZE 4096
#define CMD_SIZE 1024
#define NUM_TEST_ITERATIONS 100  // Number of iterations for timing tests
#define TEST_MESSAGE "This is a test message for performance measurement"

// Global state
extern uint8_t *public_key;
extern uint8_t *secret_key;
extern size_t sig_len;
extern size_t pk_len;
extern size_t sk_len;
extern size_t current_alg_index;

// Timing helper function
static inline double get_time_in_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

// Function declarations
bool generate_keypair(void);
bool send_public_key(int sock);
bool sign_message(const char *message, uint8_t **signature, size_t *actual_sig_len);
bool send_payload(int sock, const char *message, const uint8_t *signature, size_t signature_len);
bool sign_and_send_message(int sock, const char *message);
bool send_fake_signed_message(int sock, const char *message);
void cleanup_crypto(void);
int connect_to_server(void);
void process_command(int *sock, char* cmd, bool *running);
void list_algorithms(void);
bool set_algorithm(size_t index);
bool run_performance_test(void);

#endif // CLIENT_H