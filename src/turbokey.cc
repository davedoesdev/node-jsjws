#include <memory>
#include <string>
#include <napi.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

using namespace Napi;

void ThrowSSLError(const CallbackInfo& info, const char *msg)
{
    char buf[1024] = {0};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw Error::New(info.Env(), std::string(msg) + ": " + buf);
}

struct DeleteBIGNUM
{
    void operator()(BIGNUM *bn)
    {
        BN_free(bn);
    }
};

struct DeleteRSA
{
    void operator()(RSA* rsa)
    {
        RSA_free(rsa);
    }
};

struct DeleteBIO
{
    void operator()(BIO* bio)
    {
        BIO_vfree(bio);
    }
};

Value GeneratePrivateKey(const CallbackInfo& info)
{
    // Get arguments
    int32_t modulusBits = info[0].As<Number>();
    uint32_t exponent = info[1].As<Number>();

    // Create bignum exponent
    std::unique_ptr<BIGNUM, DeleteBIGNUM> e(BN_new());
    if (!e)
    {
        ThrowSSLError(info, "Failed to create bignum exponent");
    }
    if (!BN_set_word(e.get(), exponent))
    {
        ThrowSSLError(info, "Failed to set bignum exponent");
    }

    // Generate key
    std::unique_ptr<RSA, DeleteRSA> rsa(RSA_new());
    if (!rsa)
    {
        ThrowSSLError(info, "Failed to create RSA object");
    }
    if (!RSA_generate_key_ex(rsa.get(), modulusBits, e.get(), nullptr))
    {
        ThrowSSLError(info, "Failed to generate key");
    }

    // Convert key to PEM string
    std::unique_ptr<BIO, DeleteBIO> bio(BIO_new(BIO_s_mem()));
    if (!bio)
    {
        ThrowSSLError(info, "Failed to create memory BIO");
    }
    if (!PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr))
    {
        ThrowSSLError(info, "Failed to write private key PEM");
    }
    char *data;
    long length = BIO_get_mem_data(bio.get(), &data);
    return String::New(info.Env(), data, length);
}

void Init(Env env, Object exports, Object module)
{
    ERR_load_crypto_strings();
    exports["generatePrivateKey"] = Function::New(env, GeneratePrivateKey);
}


NODE_API_MODULE(turbokey, Init)
