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

int rlbox_SSL_get_error(SSL *ssl, int ret);
SSL_CIPHER *rlbox_SSL_get_current_cipher(SSL *ssl);
const char *rlbox_SSL_get_cipher_name(SSL *s);
long rlbox_SSL_CTX_set_options(SSL_CTX *ctx, long options);
long rlbox_SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);

//rlbox_SSL_COMP_get_compression_methods
STACK_OF(SSL_COMP) *rlbox_SSL_COMP_get_compression_methods(void);
//rlbox_SSL_CTX_set_default_verify_paths
int rlbox_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
const char *rlbox_SSL_CIPHER_get_name(SSL_CIPHER *cipher);

long rlbox_SSL_CTX_clear_mode(SSL_CTX *ctx, long mode);
long rlbox_SSL_CTX_get_mode(SSL_CTX *ctx);
long rlbox_SSL_CTX_set_tmp_ecdh(SSL_CTX *ctx, EC_KEY *ecdh);

DH* rlbox_DH_new(void);
void rlbox_DH_free(DH *dh);

BIGNUM *rlbox_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int rlbox_DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
    

EC_KEY *rlbox_EC_KEY_new_by_curve_name(int nid);

int rlbox_BIO_free(BIO *a);


int rlbox_X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME *rlbox_X509_get_issuer_name(X509 *x);
int rlbox_X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
void rlbox_X509_free(X509 *a);
int rlbox_X509_get_ext_count(X509 *x);
X509_NAME_ENTRY *rlbox_X509_NAME_get_entry(X509_NAME *name, int loc);
ASN1_OBJECT * rlbox_X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING * rlbox_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);
const unsigned char * rlbox_ASN1_STRING_get0_data(ASN1_STRING *x);
int rlbox_OBJ_obj2nid(ASN1_OBJECT *o);
const char *  rlbox_OBJ_nid2ln(int n);
const char *  rlbox_OBJ_nid2sn(int n);



int rlbox_X509_NAME_entry_count(X509_NAME *name);
int rlbox_X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos);
X509_NAME *rlbox_X509_get_subject_name(X509 *x);
X509_EXTENSION * rlbox_X509_get_ext (X509 *x, int loc);
ASN1_OBJECT *rlbox_X509_EXTENSION_get_object(X509_EXTENSION *ex);
void *rlbox_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);



BIO_METHOD *rlbox_BIO_s_mem(void);
BIO *rlbox_BIO_new(BIO_METHOD *type);
long rlbox_BIO_get_mem_data(BIO *bp, char** ptpr);
//long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

/*

X509_NAME *X509_get_subject_name(const X509 *x);

int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);

X509_NAME *X509_get_issuer_name(const X509 *x);

int X509_get_ext_count(const X509 *x);

void X509_free(X509 *a);

X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);



int X509_NAME_entry_count(const X509_NAME *name);
int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos);
X509_NAME *X509_get_subject_name(const X509 *x);
X509_EXTENSION * X509_get_ext (X509 *x, int loc)
ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex);
void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);


*/


#ifdef __cplusplus
}
#endif

// #endif // cplusplus
#endif // RLBOX_OPENSSL_H