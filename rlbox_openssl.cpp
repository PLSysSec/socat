#include "rlbox_openssl.h"
#include "assert.h"
#include <map>

#define RLBOX_SINGLE_THREADED_INVOCATIONS


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
    rlbox::tainted_opaque<T, rlbox_openssl_sandbox_type>;

template <typename T>
using tainted_volatile_openssl =
    rlbox::tainted_volatile<T, rlbox_openssl_sandbox_type>;

using rlbox::tainted_boolean_hint;


rlbox_sandbox_openssl *sandbox = NULL;
std::unordered_map<SSL_CTX*, tainted_openssl<SSL_CTX*>> ctx_map;
std::unordered_map<SSL*, tainted_openssl<SSL*>> ssl_map;
int ctx_counter = 1;
int ssl_counter = 1;

//extern "C" void SSL_library_init(void);

// extern "C" void SSL_library_init(void); // one way
// extern "C" const SSL_METHOD *SSLv2_client_method(void);

auto copy_buf_to_sandbox(  
  rlbox_sandbox_openssl* sandbox,
  const void* buf,
  int num)
{
  size_t buf_size = num;
  auto buf_tainted = sandbox->malloc_in_sandbox<char>(buf_size);
  // copy to sandbox
  std::memcpy(
    buf_tainted.unverified_safe_pointer_because(buf_size, "writing to region"),
    buf,
    buf_size);
  return buf_tainted;
}


auto copy_str_to_sandbox(  
  rlbox_sandbox_openssl* sandbox,
  const char* str)
{
  size_t str_size = strlen(str) + 1;
  auto str_tainted = sandbox->malloc_in_sandbox<char>(str_size);
  // copy to sandbox
  std::strncpy(
    str_tainted.unverified_safe_pointer_because(str_size, "writing to region"),
    str,
    str_size);
  return str_tainted;
}

extern "C" {


void rlbox_SSL_load_error_strings(void){
    //SSL_load_error_strings();
    if (sandbox == NULL){
        sandbox->create_sandbox();
    }
    sandbox->invoke_sandbox_function(OPENSSL_init_ssl, 0x00200000L | 0x00000002L, __null);
}

int rlbox_SSL_library_init(void){
    if (sandbox == NULL){
        sandbox->create_sandbox();
    }
    // auto result = sandbox->invoke_sandbox_function(
    //     OPENSSL_init_ssl, 
    //     0,
    //     __null)
    //     .copy_and_verify([](int ret){ return ret;});
    // return result;
    // SSL_library_init(); 
    //return OPENSSL_init_ssl(0, __null);
    // sandbox->invoke_sandbox_function(SSL_library_init);
}
const SSL_METHOD *rlbox_SSLv2_client_method(void){
    assert(false);
    // SSLv2_client_method();
    // tainted_openssl<const SSL_METHOD*> tainted_method = sandbox->invoke_sandbox_function(SSLv2_client_method);
    // const SSL_METHOD* m = malloc(sizeof(SSL_METHOD));
    // memcpy(m, tainted_method, sizeof(SSL_METHOD));
    // return m;
}
const SSL_METHOD *rlbox_SSLv2_server_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_SSLv3_client_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_SSLv3_server_method(void){
    assert(false);
}

const SSL_METHOD *rlbox_SSLv23_client_method(void){
    //TODO: run in sandbox
    return TLS_client_method();
}

const SSL_METHOD *rlbox_SSLv23_server_method(void){
    //TODO: run in sandbox
    return TLS_server_method();
}
const SSL_METHOD *rlbox_TLSv1_client_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_server_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_1_client_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_1_server_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_2_client_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_2_server_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_DTLSv1_client_method(void){
    assert(false);
}
const SSL_METHOD *rlbox_DTLSv1_server_method(void){
    assert(false);
}   

//TODO
SSL_CTX *rlbox_SSL_CTX_new(const SSL_METHOD *method){
    // auto tainted_ctx = sandbox->invoke_sandbox_function(SSL_CTX_new, method);
    // SSL_CTX* opaque_ctx = (SSL_CTX*) ctx_counter++;
    // ctx_map[opaque_ctx] = tainted_ctx;
    // return opaque_ctx;
}
SSL *rlbox_SSL_new(SSL_CTX *ctx){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_ssl = sandbox->invoke_sandbox_function(SSL_new, tainted_ctx);
    SSL* opaque_ssl = (SSL*) ssl_counter++;
    ssl_map[opaque_ssl] = tainted_ssl;
    return opaque_ssl;
}
int rlbox_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_CAfile = copy_str_to_sandbox(sandbox, CAfile);
    auto tainted_CApath = copy_str_to_sandbox(sandbox, CApath);
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_load_verify_locations, 
        tainted_ctx,
        tainted_CAfile, 
        tainted_CApath)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_CAfile);
    sandbox->free_in_sandbox(tainted_CApath);
    return result;
}
int rlbox_SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_file = copy_str_to_sandbox(sandbox, file);
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_use_certificate_file, 
        tainted_ctx,
        tainted_file, 
        type)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_file);
    return result;
}
int rlbox_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_file = copy_str_to_sandbox(sandbox, file);
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_use_certificate_chain_file, 
        tainted_ctx,
        tainted_file)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_file);
    return result;
}

int rlbox_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_file = copy_str_to_sandbox(sandbox, file);
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_use_PrivateKey_file, 
        tainted_ctx,
        tainted_file, 
        type)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_file);
    return result;
}

void rlbox_SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX *)){
    assert(false);
    //return SSL_CTX_set_verify(ctx, mode, verify_callback);
}
//TODO
int rlbox_SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh){
    return SSL_CTX_ctrl(ctx, 3, 0, (char *)(dh));
    //return SSL_CTX_set_tmp_dh(ctx, dh);
}
int rlbox_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_str = copy_str_to_sandbox(sandbox, str);
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_set_cipher_list, 
        tainted_ctx,
        tainted_str)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_str);
    return result;
}
int rlbox_SSL_set_cipher_list(SSL *ssl, const char *str){
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_str = copy_str_to_sandbox(sandbox, str);
    auto result = sandbox->invoke_sandbox_function(
        SSL_set_cipher_list, 
        tainted_ssl,
        tainted_str)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_str);
    return result;
}
long rlbox_SSL_get_verify_result(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_get_verify_result, 
        tainted_ssl)
        .copy_and_verify([](long ret){ return ret;});
    return result;
}
int rlbox_SSL_set_fd(SSL *ssl, int fd){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_set_fd, 
        tainted_ssl,
        fd)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

int rlbox_SSL_connect(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_connect, 
        tainted_ssl)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

int rlbox_SSL_accept(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_accept, 
        tainted_ssl)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

int rlbox_SSL_read(SSL *ssl, void *buf, int num){
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_buf = copy_buf_to_sandbox(sandbox, buf, num);
    auto result = sandbox->invoke_sandbox_function(
        SSL_read, 
        tainted_ssl,
        tainted_buf, 
        num)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_buf);
    return result;
}

int rlbox_SSL_pending(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_pending, 
        tainted_ssl)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

int rlbox_SSL_write(SSL *ssl, const void *buf, int num){
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_buf = copy_buf_to_sandbox(sandbox, buf, num);
    auto result = sandbox->invoke_sandbox_function(
        SSL_write, 
        tainted_ssl,
        tainted_buf, 
        num)
        .copy_and_verify([](int ret){ return ret;});
    sandbox->free_in_sandbox(tainted_buf);
    return result;
}

X509 *rlbox_SSL_get_peer_certificate(SSL *ssl){
    assert(false); // I don't think this will be called
    //return SSL_get_peer_certificate(ssl);
}
int rlbox_SSL_shutdown(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_shutdown, 
        tainted_ssl)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

void rlbox_SSL_CTX_free(SSL_CTX *ctx){
    auto tainted_ctx = ctx_map[ctx];
    sandbox->invoke_sandbox_function(SSL_CTX_free, tainted_ctx);
    sandbox->destroy_sandbox();
}
void rlbox_SSL_free(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    sandbox->invoke_sandbox_function(SSL_free, tainted_ssl);
}

int rlbox_RAND_egd(const char *path){
    assert(false);
    // return RAND_egd(path);
}
// TODO
DH *rlbox_PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u){
    assert(false);
    //return PEM_read_bio_DHparams(bp, x, cb, u);
}
//TODO
BIO *rlbox_BIO_new_file(const char *filename, const char *mode){
    assert(false);
    // return BIO_new_file(filename, mode);
}

int rlbox_FIPS_mode_set(int onoff){
    auto result = sandbox->invoke_sandbox_function(
        FIPS_mode_set,
        onoff)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

const COMP_METHOD *rlbox_SSL_get_current_compression(SSL *ssl){
    // auto tainted_ssl = ssl_map[ssl];
    // auto result = sandbox->invoke_sandbox_function(
    //     SSL_get_current_compression, 
    //     tainted_ssl)
    //     .copy_and_verify_range([](std::unique_ptr<int*> val) {
    //         return std::move(val);
    //   });
    // return result;
    //return SSL_get_current_compression(ssl);
}

const COMP_METHOD *rlbox_SSL_get_current_expansion(SSL *ssl){
    assert(false);
    //return rlbox_SSL_get_current_expansion(ssl);
}
//TODO
const char *rlbox_SSL_COMP_get_name(const COMP_METHOD *comp){
    assert(false);
    // return SSL_COMP_get_name(comp);
}

}