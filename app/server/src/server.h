#ifndef SERVER_H
#define SERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <oqs/oqs.h>

// Constants
#define PORT 8080
#define BUFFER_SIZE 1024

// Type definitions
typedef struct {
    uint8_t *public_key;
    size_t pk_len;
    size_t sig_len;
    size_t alg_index;
} ClientInfo;

// Function declarations
bool receive_public_key(int socket, ClientInfo *client);
bool verify_message(const uint8_t *public_key, size_t pk_len,
                   const uint8_t *message, size_t msg_len,
                   const uint8_t *signature, size_t sig_len,
                   size_t alg_index);
bool handle_client_message(int socket, ClientInfo *client);
void cleanup_client(ClientInfo *client);

#endif // SERVER_H