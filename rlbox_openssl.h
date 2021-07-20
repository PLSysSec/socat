#ifndef RLBOX_OPENSSL_H_
#define RLBOX_OPENSSL_H_


// TODO: Invoke the namespace sandbox
#ifdef WASM_SANDBOXING_OPENSSL
#  include "rlbox_lucet_sandbox.hpp"
#else
// Extra configuration for no-op sandbox
#  define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol
#  include "rlbox_noop_sandbox.hpp"
#endif

#include "rlbox.hpp"

// Choose between wasm sandbox and noop sandbox
#ifdef WASM_SANDBOXING_OPENSSL
namespace rlbox {
class rlbox_lucet_sandbox;
}
using rlbox_openssl_sandbox_type = rlbox::rlbox_lucet_sandbox;
#else
using rlbox_openssl_sandbox_type = rlbox::rlbox_noop_sandbox;
#endif


using rlbox_sandbox_openssl =
    rlbox::rlbox_sandbox<rlbox_openssl_sandbox_type>;

template <typename T>
using sandbox_callback_openssl =
    rlbox::sandbox_callback<T, rlbox_openssl_sandbox_type>;

template <typename T>
using tainted_openssl = rlbox::tainted<T, rlbox_openssl_sandbox_type>;

template <typename T>
using tainted_opaque_openssl =
    rlbox::tainted_opaque<T, rlbox_openssl_openssl_type>;

template <typename T>
using tainted_volatile_openssl =
    rlbox::tainted_volatile<T, rlbox_openssl_openssl_type>;

using rlbox::tainted_boolean_hint;

#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

extern "C" {
void rlbox_sycSSL_load_error_strings(void);
int rlbox_sycSSL_library_init(void);
const SSL_METHOD *rlbox_sycSSLv2_client_method(void);
const SSL_METHOD *rlbox_sycSSLv2_server_method(void);
const SSL_METHOD *rlbox_sycSSLv3_client_method(void);
const SSL_METHOD *rlbox_sycSSLv3_server_method(void);
const SSL_METHOD *rlbox_sycSSLv23_client_method(void);
const SSL_METHOD *rlbox_sycSSLv23_server_method(void);
const SSL_METHOD *rlbox_sycTLSv1_client_method(void);
const SSL_METHOD *rlbox_sycTLSv1_server_method(void);
const SSL_METHOD *rlbox_sycTLSv1_1_client_method(void);
const SSL_METHOD *rlbox_sycTLSv1_1_server_method(void);
const SSL_METHOD *rlbox_sycTLSv1_2_client_method(void);
const SSL_METHOD *rlbox_sycTLSv1_2_server_method(void);
const SSL_METHOD *rlbox_sycDTLSv1_client_method(void);
const SSL_METHOD *rlbox_sycDTLSv1_server_method(void);
SSL_CTX *rlbox_sycSSL_CTX_new(const SSL_METHOD *method);
SSL *rlbox_sycSSL_new(SSL_CTX *ctx);
int rlbox_sycSSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
				     const char *CApath);
int rlbox_sycSSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int rlbox_sycSSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int rlbox_sycSSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
void rlbox_sycSSL_CTX_set_verify(SSL_CTX *ctx, int mode,
			   int (*verify_callback)(int, X509_STORE_CTX *));
int rlbox_sycSSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);
int rlbox_sycSSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
int rlbox_sycSSL_set_cipher_list(SSL *ssl, const char *str);
long rlbox_sycSSL_get_verify_result(SSL *ssl);
int rlbox_sycSSL_set_fd(SSL *ssl, int fd);
int rlbox_sycSSL_connect(SSL *ssl);
int rlbox_sycSSL_accept(SSL *ssl);
int rlbox_sycSSL_read(SSL *ssl, void *buf, int num);
int rlbox_sycSSL_pending(SSL *ssl);
int rlbox_sycSSL_write(SSL *ssl, const void *buf, int num);
X509 *rlbox_sycSSL_get_peer_certificate(SSL *ssl);
int rlbox_sycSSL_shutdown(SSL *ssl);
void rlbox_sycSSL_CTX_free(SSL_CTX *ctx);
void rlbox_sycSSL_free(SSL *ssl);
int rlbox_sycRAND_egd(const char *path);

DH *rlbox_sycPEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);

BIO *rlbox_sycBIO_new_file(const char *filename, const char *mode);

int rlbox_sycFIPS_mode_set(int onoff);

}

// #if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_COMP)
// const COMP_METHOD *sycSSL_get_current_compression(SSL *ssl);
// const COMP_METHOD *sycSSL_get_current_expansion(SSL *ssl);
// const char *sycSSL_COMP_get_name(const COMP_METHOD *comp);


#endif