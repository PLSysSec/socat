#ifndef RLBOX_OPENSSL_H_
#define RLBOX_OPENSSL_H_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/rand.h>
// #include "sysincludes.h"


#ifdef __cplusplus
extern "C" {
#endif
void rlbox_SSL_load_error_strings(void);
int rlbox_SSL_library_init(void);
const SSL_METHOD *rlbox_SSLv2_client_method(void);
const SSL_METHOD *rlbox_SSLv2_server_method(void);
const SSL_METHOD *rlbox_SSLv3_client_method(void);
const SSL_METHOD *rlbox_SSLv3_server_method(void);
const SSL_METHOD *rlbox_SSLv23_client_method(void);
const SSL_METHOD *rlbox_SSLv23_server_method(void);
const SSL_METHOD *rlbox_TLSv1_client_method(void);
const SSL_METHOD *rlbox_TLSv1_server_method(void);
const SSL_METHOD *rlbox_TLSv1_1_client_method(void);
const SSL_METHOD *rlbox_TLSv1_1_server_method(void);
const SSL_METHOD *rlbox_TLSv1_2_client_method(void);
const SSL_METHOD *rlbox_TLSv1_2_server_method(void);
const SSL_METHOD *rlbox_DTLSv1_client_method(void);
const SSL_METHOD *rlbox_DTLSv1_server_method(void);
SSL_CTX *rlbox_SSL_CTX_new(const SSL_METHOD *method);
SSL *rlbox_SSL_new(SSL_CTX *ctx);
int rlbox_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
				     const char *CApath);
int rlbox_SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int rlbox_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int rlbox_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
void rlbox_SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
			   int (*verify_callback)(int, X509_STORE_CTX *));
int rlbox_SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);
int rlbox_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
int rlbox_SSL_set_cipher_list(SSL *ssl, const char *str);
long rlbox_SSL_get_verify_result(SSL *ssl);
int rlbox_SSL_set_fd(SSL *ssl, int fd);
int rlbox_SSL_connect(SSL *ssl);
int rlbox_SSL_accept(SSL *ssl);
int rlbox_SSL_read(SSL *ssl, void *buf, int num);
int rlbox_SSL_pending(SSL *ssl);
int rlbox_SSL_write(SSL *ssl, const void *buf, int num);
X509 *rlbox_SSL_get_peer_certificate(SSL *ssl);
int rlbox_SSL_shutdown(SSL *ssl);
void rlbox_SSL_CTX_free(SSL_CTX *ctx);
void rlbox_SSL_free(SSL *ssl);
int rlbox_RAND_egd(const char *path);

DH *rlbox_PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);

BIO *rlbox_BIO_new_file(const char *filename, const char *mode);

int rlbox_FIPS_mode_set(int onoff);

// #if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_COMP)
const COMP_METHOD *rlbox_SSL_get_current_compression(SSL *ssl);
const COMP_METHOD *rlbox_SSL_get_current_expansion(SSL *ssl);
const char *rlbox_SSL_COMP_get_name(const COMP_METHOD *comp);

#ifdef __cplusplus
}
#endif

// #endif // cplusplus
#endif // RLBOX_OPENSSL_H