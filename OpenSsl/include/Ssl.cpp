#include "Ssl.h"

// Initialize OpenSSL
void init_openssl() 
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Clean up OpenSSL
void cleanup_openssl() 
{
    EVP_cleanup();
}

// Create SSL context
SSL_CTX* create_context(int type) 
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    switch (type)
    {
    case CLIENT:
        method = SSLv23_client_method();// Use SSLv23_client_method for compatibility
        break;
    case SERVER:
        method = SSLv23_server_method(); // Use SSLv23_server_method for compatibility
        break;
    default:
        exit(0);
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    switch (type)
    {
    case SERVER:
        // Load server certificate and private key
        if (SSL_CTX_use_certificate_file(ctx, "/etc/cups/ssl/server.crt", SSL_FILETYPE_PEM) <= 0) {
            perror("Unable to load server certificate");
            exit(EXIT_FAILURE);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/cups/ssl/server.key", SSL_FILETYPE_PEM) <= 0 ) {
            perror("Unable to load server private key");
            exit(EXIT_FAILURE);
        }
        break;
    
    default:
        break;
    }

    return ctx;
}


