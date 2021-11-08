#include "rlbox_openssl.h"
#include "assert.h"
#include <map>
#include <openssl/bn.h>


#define RLBOX_SINGLE_THREADED_INVOCATIONS


// TODO: Invoke the namespace sandbox
// #ifdef WASM_SANDBOXING_OPENSSL
// #  include "rlbox_lucet_sandbox.hpp"
// #else
// // Extra configuration for no-op sandbox
#  define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol
#  include "rlbox_noop_sandbox.hpp"
// #endif

#include "rlbox.hpp"

// Choose between wasm sandbox and noop sandbox
// #ifdef WASM_SANDBOXING_OPENSSL
// namespace rlbox {
// class rlbox_lucet_sandbox;
// }
// using rlbox_openssl_sandbox_type = rlbox::rlbox_lucet_sandbox;
// #else
using rlbox_openssl_sandbox_type = rlbox::rlbox_noop_sandbox;
// #endif


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


template <typename T>
using taint_map_openssl = std::unordered_map<T, tainted_openssl<T>>;


using rlbox::tainted_boolean_hint;


rlbox_sandbox_openssl *sandbox;
taint_map_openssl<SSL_CTX*> ctx_map;
taint_map_openssl<SSL*> ssl_map;
taint_map_openssl<const SSL_METHOD*> method_map;
taint_map_openssl<DH*> dh_map;
taint_map_openssl<EC_KEY*> ec_key_map;
taint_map_openssl<const SSL_CIPHER*> ssl_cipher_map;


taint_map_openssl<BIGNUM*> bignum_map;
taint_map_openssl<BIO*> bio_map;
taint_map_openssl<X509*> x509_map;

taint_map_openssl<X509_NAME*> x509_name_map;
taint_map_openssl<X509_NAME_ENTRY*> x509_name_entry_map;
taint_map_openssl<X509_EXTENSION*> x509_extension_map;

taint_map_openssl<ASN1_OBJECT*> asn1_object_map;
taint_map_openssl<ASN1_STRING*> asn1_string_map;

taint_map_openssl<const COMP_METHOD*> comp_method_map;



//std::unordered_map<SSL_CTX*, tainted_openssl<SSL_CTX*>> ctx_map;
//std::unordered_map<SSL*, tainted_openssl<SSL*>> ssl_map;
// std::unordered_map<const SSL_METHOD*, tainted_openssl<const SSL_METHOD*>> method_map;
// std::unordered_map<DH*, tainted_openssl<DH*>> dh_map;
// std::unordered_map<EC_KEY*, tainted_openssl<EC_KEY*>> ec_key_map;
// std::unordered_map<BIGNUM*, tainted_openssl<BIGNUM*>> bignum_map;
// std::unordered_map<BIO*, tainted_openssl<BIO*>> bio_map;
// std::unordered_map<X509*, tainted_openssl<X509*>> x509_map;

// std::unordered_map<X509_NAME*, tainted_openssl<X509_NAME*>> x509_name_map;
// std::unordered_map<X509_NAME_ENTRY*, tainted_openssl<X509_NAME_ENTRY*>> x509_name_entry_map;
// std::unordered_map<X509_EXTENSION*, tainted_openssl<X509_EXTENSION*>> x509_extension_map;

// std::unordered_map<ASN1_OBJECT*, tainted_openssl<ASN1_OBJECT*>> asn1_object_map;
// std::unordered_map<ASN1_STRING*, tainted_openssl<ASN1_STRING*>> asn1_string_map;

std::unordered_map<BIO_METHOD*, tainted_openssl<const BIO_METHOD*>> bio_method_map;


int ctx_counter = 1;
int ssl_counter = 1;
int method_counter = 1;
int dh_counter = 1;
int bignum_counter = 1;
int ec_key_counter = 1;
int ssl_cipher_counter = 1;

int bio_counter = 1;
int x509_counter = 1;

int x509_name_counter = 1;
int x509_name_entry_counter = 1;
int x509_extension_counter = 1;

int asn1_object_counter = 1;
int asn1_string_counter = 1;

int bio_method_counter = 1;

int comp_method_counter = 1;


// // Maps keys of type K to tainted<V>
// template <typename K, typename V>
// class ProxyMap {
// private:
//     std::unordered_map<K, tainted_openssl<V>> map;
//     taint_map_openssl<K> map;
//     int counter;
  
// public:
//     ProxyMap();
//     tainted_openssl<V> lookup(K key);
// };

// template <typename T>
// ProxyMap<T>::ProxyMap(T arr[], int s)
// {
//     ptr = new T[s];
//     size = s;
//     for (int i = 0; i < size; i++)
//         ptr[i] = arr[i];
// }


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
//   if (str == nullptr){
//       return nullptr;
//   }
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
    // printf("SSL_load_error_strings\n");
    static rlbox_sandbox_openssl tmp_sandbox;
    tmp_sandbox.create_sandbox();
    sandbox = &tmp_sandbox;
    // if (sandbox == NULL){
    //sandbox.create_sandbox();
    // }
    sandbox->invoke_sandbox_function(OPENSSL_init_ssl, 0x00200000L | 0x00000002L, nullptr);
}

int rlbox_SSL_library_init(void){
    // printf("SSL_library_init\n");
    // if (sandbox == NULL){
    //     sandbox->create_sandbox();
    // }
    auto result = sandbox->invoke_sandbox_function(
        OPENSSL_init_ssl, 
        0,
        nullptr)
        .copy_and_verify([](int ret){ return ret;});
    return result;
    // SSL_library_init(); 
    //return OPENSSL_init_ssl(0, __null);
    // sandbox->invoke_sandbox_function(SSL_library_init);
}
const SSL_METHOD *rlbox_SSLv2_client_method(void){
    printf("TODO: rlbox_SSLv2_client_method\n");
    assert(false);
    // SSLv2_client_method();
    // tainted_openssl<const SSL_METHOD*> tainted_method = sandbox->invoke_sandbox_function(SSLv2_client_method);
    // const SSL_METHOD* m = malloc(sizeof(SSL_METHOD));
    // memcpy(m, tainted_method, sizeof(SSL_METHOD));
    // return m;
}
const SSL_METHOD *rlbox_SSLv2_server_method(void){
    printf("TODO: rlbox_SSLv2_server_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_SSLv3_client_method(void){
    printf("TODO: rlbox_SSLv3_client_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_SSLv3_server_method(void){
    printf("TODO: rlbox_SSLv3_server_method\n");
    assert(false);
}

const SSL_METHOD *rlbox_SSLv23_client_method(void){
    auto tainted_method = sandbox->invoke_sandbox_function(TLS_client_method);
    const SSL_METHOD* opaque_method = (const SSL_METHOD*) method_counter++;
    method_map[opaque_method] = tainted_method;
    return opaque_method;
}

const SSL_METHOD *rlbox_SSLv23_server_method(void){
    auto tainted_method = sandbox->invoke_sandbox_function(TLS_server_method);
    const SSL_METHOD* opaque_method = (const SSL_METHOD*) method_counter++;
    method_map[opaque_method] = tainted_method;
    return opaque_method;
}
const SSL_METHOD *rlbox_TLSv1_client_method(void){
    printf("TODO: rlbox_TLSv1_client_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_server_method(void){
    printf("TODO: rlbox_TLSv1_server_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_1_client_method(void){
    printf("TODO: rlbox_TLSv1_1_client_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_1_server_method(void){
    printf("TODO: rlbox_TLSv1_1_server_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_2_client_method(void){
    printf("TODO: rlbox_TLSv1_2_client_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_TLSv1_2_server_method(void){
    printf("TODO: rlbox_TLSv1_2_server_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_DTLSv1_client_method(void){
    printf("TODO: rlbox_DTLSv1_client_method\n");
    assert(false);
}
const SSL_METHOD *rlbox_DTLSv1_server_method(void){
    printf("TODO: rlbox_DTLSv1_server_method\n");
    assert(false);
}   

SSL_CTX *rlbox_SSL_CTX_new(const SSL_METHOD *method){
    auto tainted_method = method_map[method];
    auto tainted_ctx = sandbox->invoke_sandbox_function(SSL_CTX_new, tainted_method);
    SSL_CTX* opaque_ctx = (SSL_CTX*) ctx_counter++;
    ctx_map[opaque_ctx] = tainted_ctx;
    return opaque_ctx;
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
    auto tainted_CAfile = (CAfile == nullptr) ? nullptr : copy_str_to_sandbox(sandbox, CAfile);
    auto tainted_CApath = (CApath == nullptr) ? nullptr : copy_str_to_sandbox(sandbox, CApath);
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
    assert(verify_callback == nullptr);
    auto tainted_ctx = ctx_map[ctx];
    sandbox->invoke_sandbox_function(
        SSL_CTX_set_verify, 
        tainted_ctx, 
        mode,
        nullptr);
    return;
    //assert(false);
    //return SSL_CTX_set_verify(ctx, mode, verify_callback);
}

DH* rlbox_DH_new(void){
    auto tainted_dh = sandbox->invoke_sandbox_function(DH_new);
    DH* opaque_dh = (DH*) dh_counter++;
    dh_map[opaque_dh] = tainted_dh;
    return opaque_dh;
}

int rlbox_SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_dh = dh_map[dh];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_ctrl, 
        tainted_ctx,
        3, 
        0,
        tainted_dh)
        .copy_and_verify([](int ret){ return ret;});
    return result;
    
    // return SSL_CTX_ctrl(ctx, 3, 0, (char *)(dh));
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
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_x509 = sandbox->invoke_sandbox_function(
        SSL_get_peer_certificate, 
        tainted_ssl);
    X509* opaque_x509 = (X509*) x509_counter++;
    x509_map[opaque_x509] = tainted_x509;
    return opaque_x509;
    // printf("TODO: rlbox_SSL_get_peer_certificate\n");
    // assert(false); // I don't think this will be called
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
    printf("TODO: rlbox_RAND_egd\n");
    assert(false);
    // return RAND_egd(path);
}
// TODO
DH *rlbox_PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u){
    auto tainted_bp = bio_map[bp];
    assert(x == nullptr);
    assert(cb == nullptr);
    assert(u == nullptr);
    auto tainted_dh = sandbox->invoke_sandbox_function(
        PEM_read_bio_DHparams, 
        tainted_bp,
        nullptr,
        nullptr,
        nullptr);
    
    // printf("tainted_dh = %p tainted_bp = %p \n", tainted_dh, tainted_bp);
    // for( const auto& n : dh_map ) {
    //     printf("%p %p\n", n.first, n.second);
    //     // std::cout << "Key:[" << n.first << "] Value:[" << n.second << "]\n";
    // }
    DH* opaque_dh = (DH*) dh_counter++;
    dh_map[opaque_dh] = tainted_dh;
    return opaque_dh;

    // auto result = reverse_dh_map.find(tainted_dh);
    // if (result == reverse_dh_map.end()) {
    //     DH* opaque_dh = (DH*) dh_counter++;
    //     dh_map[opaque_dh] = tainted_dh;
    //     return opaque_dh;
    // } else {
    //     return result->second;
    // }
}

BIO *rlbox_BIO_new_file(const char *filename, const char *mode){
    auto tainted_filename = copy_str_to_sandbox(sandbox, filename);
    auto tainted_mode = copy_str_to_sandbox(sandbox, mode);
    auto tainted_bio = sandbox->invoke_sandbox_function(BIO_new_file, 
        tainted_filename,
        tainted_mode);
    BIO* opaque_bio = (BIO*) bio_counter++;
    bio_map[opaque_bio] = tainted_bio;
    return opaque_bio;
}


int rlbox_FIPS_mode_set(int onoff){
    assert(false);
    // auto result = sandbox->invoke_sandbox_function(
    //     FIPS_mode_set,
    //     onoff)
    //     .copy_and_verify([](int ret){ return ret;});
    // return result;
}

const COMP_METHOD *rlbox_SSL_get_current_compression(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_comp_method = sandbox->invoke_sandbox_function(
        SSL_get_current_compression, 
        tainted_ssl);

    COMP_METHOD* opaque_comp_method = (COMP_METHOD*) comp_method_counter++;
    comp_method_map[opaque_comp_method] = tainted_comp_method;
    return opaque_comp_method;

    // printf("TODO: rlbox_SSL_get_current_compression\n");
    // assert(false);
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

    auto tainted_ssl = ssl_map[ssl];
    auto tainted_comp_method = sandbox->invoke_sandbox_function(
        SSL_get_current_expansion, 
        tainted_ssl);

    COMP_METHOD* opaque_comp_method = (COMP_METHOD*) comp_method_counter++;
    comp_method_map[opaque_comp_method] = tainted_comp_method;
    return opaque_comp_method;

}
//TODO
const char *rlbox_SSL_COMP_get_name(const COMP_METHOD *comp){

    auto tainted_comp_method = comp_method_map[comp];
    auto result = sandbox->invoke_sandbox_function(
        SSL_COMP_get_name, 
        tainted_comp_method);
    return result.UNSAFE_unverified();

    // printf("TODO: rlbox_SSL_COMP_get_name\n");
    // assert(false);
    // return SSL_COMP_get_name(comp);
}

int rlbox_SSL_get_error(SSL *ssl, int ret){
    auto tainted_ssl = ssl_map[ssl];
    auto result = sandbox->invoke_sandbox_function(
        SSL_get_error, 
        tainted_ssl,
        ret)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

SSL_CIPHER *rlbox_SSL_get_current_cipher(SSL *ssl){
    auto tainted_ssl = ssl_map[ssl];
    auto tainted_cipher = sandbox->invoke_sandbox_function(
        SSL_get_current_cipher, 
        tainted_ssl);

    SSL_CIPHER* opaque_cipher = (SSL_CIPHER*) ssl_cipher_counter++;
    ssl_cipher_map[opaque_cipher] = tainted_cipher;
    return opaque_cipher;
}

const char *rlbox_SSL_get_cipher_name(SSL *s){
    printf("TODO: rlbox_SSL_get_cipher_name\n");
    assert(false);
    // auto tainted_s = ssl_map[s];
    // auto result = sandbox->invoke_sandbox_function(
    //     SSL_get_cipher_name, 
    //     tainted_s)
    //     .copy_and_verify_string([](std::unique_ptr<char[]> val) {
    //     return std::move(val);
    //   });
    // return result;
}

long rlbox_SSL_CTX_set_options(SSL_CTX *ctx, long options){
    auto tainted_ctx = ctx_map[ctx];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_set_options, 
        tainted_ctx,
        options)
        .copy_and_verify([](long ret){ return ret;});
    return result;
}

long rlbox_SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg){
    printf("TODO: rlbox_SSL_CTX_ctrl\n");
    assert(false);
}

int rlbox_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx){
    auto tainted_ctx = ctx_map[ctx];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_set_default_verify_paths, 
        tainted_ctx)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}


STACK_OF(SSL_COMP) *rlbox_SSL_COMP_get_compression_methods(void){
    printf("TODO: rlbox_SSL_COMP_get_compression_methods\n");
    assert(false);
}

const char *rlbox_SSL_CIPHER_get_name(SSL_CIPHER *cipher){
    //printf("TODO: rlbox_SSL_CIPHER_get_name\n");
    auto tainted_cipher = ssl_cipher_map[cipher];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CIPHER_get_name, 
        tainted_cipher).UNSAFE_unverified();
    return result;
    //assert(false);
}


}

long rlbox_SSL_CTX_clear_mode(SSL_CTX *ctx, long mode){
    auto tainted_ctx = ctx_map[ctx];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_ctrl,
        tainted_ctx,
        SSL_CTRL_CLEAR_MODE,
        mode,
        nullptr).copy_and_verify([](long ret){ return ret;});
    return result;
}

long rlbox_SSL_CTX_get_mode(SSL_CTX *ctx){
    auto tainted_ctx = ctx_map[ctx];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_ctrl,
        tainted_ctx,
        SSL_CTRL_MODE,
        0,
        nullptr).copy_and_verify([](long ret){ return ret;});
    return result;
}

long rlbox_SSL_CTX_set_tmp_ecdh(SSL_CTX *ctx, EC_KEY *ecdh){
    auto tainted_ctx = ctx_map[ctx];
    auto tainted_ecdh = ec_key_map[ecdh];
    auto result = sandbox->invoke_sandbox_function(
        SSL_CTX_ctrl, 
        tainted_ctx,
        4, 
        0,
        tainted_ecdh)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

void rlbox_DH_free(DH *dh){
    auto tainted_dh = dh_map[dh];
    sandbox->invoke_sandbox_function(DH_free, tainted_dh);
}

// auto copy_bignum_to_sandbox(const BIGNUM* num)
// {
//   //size_t sz = sizeof(BIGNUM);
//   size_t sz = BN_num_bytes(num);
// //   assert(false);
//   auto tainted_num = sandbox->malloc_in_sandbox<char>(sz);

//   // copy to sandbox
//   std::memcpy(
//     tainted_num.unverified_safe_pointer_because(sz, "writing to region"), //dst
//     num,       //src
//     sz);    //size

//   return tainted_num;
// }

tainted_openssl<unsigned char*> copy_unsigned_str_to_sandbox(const unsigned char* str, int len){
//   perror("before: ");
//   auto test_malloc = malloc(len);
//   printf("test_malloc: %p\n", test_malloc);
  auto str_tainted = sandbox->malloc_in_sandbox<unsigned char>(len);
//   printf("copy_str_to_sandbox! str_tainted = %p \n", str_tainted.UNSAFE_unverified());
    // TODO: transition back to malloc_in_sandbox

//   if (str_tainted.UNSAFE_unverified() == nullptr) {
//       perror("copy_unsigned_str_to_sandbox malloc: ");
//   }
  // copy to sandbox
  std::memcpy(
    // str_tainted,
    str_tainted.UNSAFE_unverified(),//.unverified_safe_pointer_because(len, "writing to region"),
    str,
    len);
  return str_tainted;
}


BIGNUM *rlbox_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret){
    printf("rlbox_BN_bin2bn start! s = %p len = %d\n", s, len);
    auto tainted_s = copy_unsigned_str_to_sandbox(s, len);
    auto tainted_bignum = sandbox->invoke_sandbox_function(BN_bin2bn,
        tainted_s,
        len,
        nullptr);
    printf("rlbox_BN_bin2bn exited sandbox!\n");
    BIGNUM* opaque_bignum = (BIGNUM*) bignum_counter++;
    bignum_map[opaque_bignum] = tainted_bignum;
    printf("rlbox_BN_bin2bn end!\n");
    return opaque_bignum;
}

int rlbox_DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g){
    printf("rlbox_DH_set0_pqg start!\n");
    auto tainted_dh = dh_map[dh];
    auto tainted_p = bignum_map[p];
    auto tainted_q = bignum_map[q];
    auto tainted_g = bignum_map[g];
    auto result = sandbox->invoke_sandbox_function(DH_set0_pqg, 
        tainted_dh,
        tainted_p,
        tainted_q,
        tainted_g).copy_and_verify([](int ret){ return ret;});
    printf("rlbox_DH_set0_pqg end!\n");
    return result;
}

EC_KEY *rlbox_EC_KEY_new_by_curve_name(int nid){
    auto tainted_ecdh = sandbox->invoke_sandbox_function(EC_KEY_new_by_curve_name, nid);
    EC_KEY* opaque_ecdh = (EC_KEY*) ec_key_counter++;
    ec_key_map[opaque_ecdh] = tainted_ecdh;
    return opaque_ecdh;
}

int rlbox_BIO_free(BIO *a){
    auto tainted_bio = bio_map[a];
    auto result = sandbox->invoke_sandbox_function(
        BIO_free, 
        tainted_bio)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}







int rlbox_X509_set_subject_name(X509 *x, X509_NAME *name){
    auto tainted_x = x509_map[x];
    auto tainted_name = x509_name_map[name];
    auto result = sandbox->invoke_sandbox_function(
        X509_set_subject_name, 
        tainted_x,
        tainted_name)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

X509_NAME *rlbox_X509_get_issuer_name(X509 *x){
    auto tainted_x = x509_map[x];
    auto tainted_x509_name = sandbox->invoke_sandbox_function(
        X509_get_issuer_name, 
        tainted_x);

    X509_NAME* opaque_x509_name = (X509_NAME*) x509_name_counter++;
    x509_name_map[opaque_x509_name] = tainted_x509_name;
    return opaque_x509_name;
}

int rlbox_X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags){
    auto tainted_out = bio_map[out];
    auto tainted_nm = x509_name_map[nm];
    auto result = sandbox->invoke_sandbox_function(
        X509_NAME_print_ex, 
        tainted_out,
        tainted_nm,
        indent,
        flags)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

void rlbox_X509_free(X509 *a){
    auto tainted_a = x509_map[a];
    sandbox->invoke_sandbox_function(
        X509_free, 
        tainted_a);
}

int rlbox_X509_get_ext_count(X509 *x){
    auto tainted_x = x509_map[x];
    auto result = sandbox->invoke_sandbox_function(
        X509_get_ext_count, 
        tainted_x)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

X509_NAME_ENTRY *rlbox_X509_NAME_get_entry(X509_NAME *name, int loc){
    auto tainted_name = x509_name_map[name];
    auto tainted_x509_name_entry = sandbox->invoke_sandbox_function(
        X509_NAME_get_entry, 
        tainted_name, 
        loc);

    X509_NAME_ENTRY* opaque_x509_name_entry = (X509_NAME_ENTRY*) x509_name_entry_counter++;
    x509_name_entry_map[opaque_x509_name_entry] = tainted_x509_name_entry;
    return opaque_x509_name_entry;
}

ASN1_OBJECT * rlbox_X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne){
    auto tainted_ne = x509_name_entry_map[ne];
    auto tainted_asn1_object = sandbox->invoke_sandbox_function(
        X509_NAME_ENTRY_get_object, 
        tainted_ne);

    ASN1_OBJECT* opaque_asn1_object = (ASN1_OBJECT*) asn1_object_counter++;
    asn1_object_map[opaque_asn1_object] = tainted_asn1_object;
    return opaque_asn1_object;
}

ASN1_STRING * rlbox_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne){
    auto tainted_ne = x509_name_entry_map[ne];
    auto tainted_asn1_string = sandbox->invoke_sandbox_function(
        X509_NAME_ENTRY_get_data, 
        tainted_ne);

    ASN1_STRING* opaque_asn1_string = (ASN1_STRING*) asn1_string_counter++;
    asn1_string_map[opaque_asn1_string] = tainted_asn1_string;
    return opaque_asn1_string;
}

const unsigned char * rlbox_ASN1_STRING_get0_data(ASN1_STRING *x){
    //printf("TODO: rlbox_ASN1_STRING_get0_data\n");
    auto tainted_x = asn1_string_map[x];
    auto result = sandbox->invoke_sandbox_function(
        ASN1_STRING_get0_data, 
        tainted_x).UNSAFE_unverified();
    return result;
    //     .copy_and_verify_string(
    //       [](std::unique_ptr<char[]> val) {
    //      return std::move(val);
    //   });
    //   return result.get();


    //assert(false);
}

int rlbox_OBJ_obj2nid(ASN1_OBJECT *o){
    auto tainted_o = asn1_object_map[o];
    auto result = sandbox->invoke_sandbox_function(
        OBJ_obj2nid, 
        tainted_o)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

const char *rlbox_OBJ_nid2ln(int n){
    auto result = sandbox->invoke_sandbox_function(OBJ_nid2ln, n).UNSAFE_unverified();
    return result;
}

const char *rlbox_OBJ_nid2sn(int n){
    auto result = sandbox->invoke_sandbox_function(OBJ_nid2ln, n).UNSAFE_unverified();
    return result;
}



int rlbox_X509_NAME_entry_count(X509_NAME *name){
    auto tainted_name = x509_name_map[name];
    auto result = sandbox->invoke_sandbox_function(
        X509_NAME_entry_count, 
        tainted_name)
        .copy_and_verify([](int ret){ return ret;});
    return result;
}

int rlbox_X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos){
    auto tainted_name = x509_name_map[name];
    auto result = sandbox->invoke_sandbox_function(
        X509_NAME_get_index_by_NID, 
        tainted_name,
        nid,
        lastpos)
        .copy_and_verify([](int ret){ return ret;});
    return result;
    assert(false);
}

X509_NAME *rlbox_X509_get_subject_name(X509 *x){
    auto tainted_x = x509_map[x];
    auto tainted_x509_name = sandbox->invoke_sandbox_function(
        X509_get_subject_name, 
        tainted_x);

    X509_NAME* opaque_x509_name = (X509_NAME*) x509_name_counter++;
    x509_name_map[opaque_x509_name] = tainted_x509_name;
    return opaque_x509_name;
}

X509_EXTENSION * rlbox_X509_get_ext (X509 *x, int loc){
    auto tainted_x = x509_map[x];
    auto tainted_x509_extension = sandbox->invoke_sandbox_function(
        X509_get_ext, 
        tainted_x,
        loc);

    X509_EXTENSION* opaque_x509_extension = (X509_EXTENSION*) x509_extension_counter++;
    x509_extension_map[opaque_x509_extension] = tainted_x509_extension;
    return opaque_x509_extension;
}

ASN1_OBJECT *rlbox_X509_EXTENSION_get_object(X509_EXTENSION *ex){
    auto tainted_ex = x509_extension_map[ex];
    auto tainted_asn1_object = sandbox->invoke_sandbox_function(
        X509_EXTENSION_get_object, 
        tainted_ex);

    ASN1_OBJECT* opaque_asn1_object = (ASN1_OBJECT*) asn1_object_counter++;
    asn1_object_map[opaque_asn1_object] = tainted_asn1_object;
    return opaque_asn1_object;
}

void *rlbox_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx){
    printf("TODO: rlbox_X509_get_ext_d2i\n");
    assert(false);
}



BIO_METHOD *rlbox_BIO_s_mem(void){
    auto tainted_bio_method = sandbox->invoke_sandbox_function(BIO_s_mem);
    BIO_METHOD* opaque_bio_method = (BIO_METHOD*) bio_method_counter++;
    bio_method_map[opaque_bio_method] = tainted_bio_method;
    return opaque_bio_method;
}

BIO *rlbox_BIO_new(BIO_METHOD *type){
    //auto tainted_bio_method = copy_str_to_sandbox(sandbox, filename);
    auto tainted_bio_method = bio_method_map[type];
    auto tainted_bio = sandbox->invoke_sandbox_function(BIO_new, 
        tainted_bio_method);
    BIO* opaque_bio = (BIO*) bio_counter++;
    bio_map[opaque_bio] = tainted_bio;
    return opaque_bio;
}

long rlbox_BIO_get_mem_data(BIO *bp, char** pptr){
    assert(pptr != nullptr);
    assert(*pptr == nullptr);
    
    auto tainted_bp = bio_map[bp];
    auto tainted_pptr = sandbox->malloc_in_sandbox<char*>(1);

    *tainted_pptr = nullptr;
    //*tainted_pptr = *pptr; 

    auto result = sandbox->invoke_sandbox_function(
        BIO_ctrl,
        tainted_bp,
        BIO_CTRL_INFO,
        0,
        tainted_pptr)
        .copy_and_verify([](long ret){ return ret;});

    *pptr = *tainted_pptr.UNSAFE_unverified();
    return result;
}


/*

int X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME *X509_get_issuer_name(const X509 *x)
X509_NAME_print_ex
void X509_free(X509 *a);
int X509_get_ext_count(const X509 *x);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
ASN1_OBJECT * X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne);
const unsigned char * ASN1_STRING_get0_data(const ASN1_STRING *x);
int OBJ_obj2nid(const ASN1_OBJECT *o);
const char *  OBJ_nid2ln(int n);
 
*/
