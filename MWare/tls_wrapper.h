// ============================================================================
// tls_wrapper.h — OpenSSL TLS Wrapper for C2 Communication
// ============================================================================
// Provides client and server TLS functions that replace raw socket send/recv.
// Only active on macOS (__APPLE__). On Windows, falls back to raw sockets.
// Usage:
//   Client: tls_init() → tls_create_client_ctx() → tls_wrap(sock) →
//           tls_connect(ssl) → tls_read/tls_write → tls_shutdown()
//   Server: tls_init() → tls_create_server_ctx(cert,key) → tls_wrap(sock) →
//           tls_accept(ssl) → tls_read/tls_write → tls_shutdown()
// ============================================================================
#pragma once

#include <string>

#ifdef __APPLE__
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

// ============================================================================
// Initialization & Cleanup
// ============================================================================
// Call tls_init() once at program startup, tls_cleanup() at shutdown.
bool    tls_init();
void    tls_cleanup();

// ============================================================================
// Context Creation
// ============================================================================
// Client context: no certificate needed (accepts self-signed)
void*   tls_create_client_ctx();

// Server context: requires cert.pem and key.pem file paths
void*   tls_create_server_ctx(const char* cert_file, const char* key_file);

// Free context (call after all SSL connections are closed)
void    tls_free_ctx(void* ctx);

// ============================================================================
// Connection Wrapping
// ============================================================================
// Wrap an existing TCP socket with TLS. Returns SSL* as void*.
void*   tls_wrap_socket(void* ctx, int socket_fd);

// Client: perform TLS handshake over connected socket
bool    tls_connect(void* ssl);

// Server: perform TLS handshake over accepted socket
bool    tls_accept(void* ssl);

// ============================================================================
// I/O — Drop-in replacements for send()/recv()
// ============================================================================
int     tls_read(void* ssl, char* buf, int len);
int     tls_write(void* ssl, const char* buf, int len);

// ============================================================================
// Shutdown
// ============================================================================
// Gracefully shut down TLS connection and free SSL object
void    tls_shutdown(void* ssl);
