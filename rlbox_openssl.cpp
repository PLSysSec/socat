#include "rlbox_openssl.h"

using namespace rlbox;

extern "C" {

void rlbox_sycSSL_load_error_strings(void){

}
int rlbox_sycSSL_library_init(void){

}
const SSL_METHOD *rlbox_sycSSLv2_client_method(void){

}
const SSL_METHOD *rlbox_sycSSLv2_server_method(void){

}
const SSL_METHOD *rlbox_sycSSLv3_client_method(void){

}
const SSL_METHOD *rlbox_sycSSLv3_server_method(void){

}
const SSL_METHOD *rlbox_sycSSLv23_client_method(void){

}
const SSL_METHOD *rlbox_sycSSLv23_server_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_client_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_server_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_1_client_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_1_server_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_2_client_method(void){

}
const SSL_METHOD *rlbox_sycTLSv1_2_server_method(void){

}
const SSL_METHOD *rlbox_sycDTLSv1_client_method(void){

}
const SSL_METHOD *rlbox_sycDTLSv1_server_method(void){

}

SSL_CTX *rlbox_sycSSL_CTX_new(const SSL_METHOD *method){

}
SSL *rlbox_sycSSL_new(SSL_CTX *ctx){

}
int rlbox_sycSSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
				     const char *CApath){

                     }
int rlbox_sycSSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type){

}
int rlbox_sycSSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file){

}
int rlbox_sycSSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type){

}
void rlbox_sycSSL_CTX_set_verify(SSL_CTX *ctx, int mode,
			   int (*verify_callback)(int, X509_STORE_CTX *)){

               }
int rlbox_sycSSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh){

}
int rlbox_sycSSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str){

}
int rlbox_sycSSL_set_cipher_list(SSL *ssl, const char *str){

}
long rlbox_sycSSL_get_verify_result(SSL *ssl){

}
int rlbox_sycSSL_set_fd(SSL *ssl, int fd){

}
int rlbox_sycSSL_connect(SSL *ssl){

}
int rlbox_sycSSL_accept(SSL *ssl){

}
int rlbox_sycSSL_read(SSL *ssl, void *buf, int num){

}
int rlbox_sycSSL_pending(SSL *ssl){

}
int rlbox_sycSSL_write(SSL *ssl, const void *buf, int num){

}
X509 *rlbox_sycSSL_get_peer_certificate(SSL *ssl){

}
int rlbox_sycSSL_shutdown(SSL *ssl){

}
void rlbox_sycSSL_CTX_free(SSL_CTX *ctx){

}
void rlbox_sycSSL_free(SSL *ssl){

}
int rlbox_sycRAND_egd(const char *path){

}

DH *rlbox_sycPEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u){

}

BIO *rlbox_sycBIO_new_file(const char *filename, const char *mode){

}

int rlbox_sycFIPS_mode_set(int onoff){

}

}
