#include "engine_factory.hpp"
#include <openssl/engine.h>

namespace Factory {
namespace SoftwareImpl {


std::size_t EngineFactory::Size() const noexcept
{
    return sizeof(EngineFactory);
}

int EngineFactory::Init() noexcept
{
    return 1;
}

int EngineFactory::Finish() noexcept
{
    return 1;
}

int EngineFactory::CtrlCmd(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) noexcept
{
    int ok = 0;
    switch (cmd) {
    case ENGINE_CTRL_SET_LOGSTREAM:
        ok = LoadCertFromString(p);
        break;
    case ENGINE_CTRL_GET_CMD_FROM_NAME:
        ok = ParseCmdString(p);
        break;
    default:
        ok = ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED;
        break;
    }

  return ok;
}


int EngineFactory::LoadCertFromString(void *cert_ptr) noexcept
{
    int ok = 0;
    // structure to fill
    struct params {
        const char *cert_id;
        X509 *cert;
    };

    // cast to params
    params *p = static_cast<params *>(cert_ptr);

    // determine if npkcs11 uri

    // load certificate from filesystem
    BIO *cert_bio = BIO_new_file(p->cert_id, "r");
    if (cert_bio) {
        p->cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        if (p->cert) {
        ok = 1;
        }
    }
    BIO_free(cert_bio);

    return ok;
}

std::unique_ptr<FactoryCipher> EngineFactory::GetCipher(int nid) noexcept 
{
    std::unique_ptr<FactoryCipher> cipher {nullptr};
    switch(nid)
    {
        case NID_aes_256_cbc:
            {auto *sw_cipher = new SwAes256Cbc();
            cipher = static_cast<std::unique_ptr<FactoryCipher>>(sw_cipher);
            break;}
        case NID_aes_256_gcm:
            {auto *sw_cipher = new SwAes256Gcm();
            cipher = static_cast<std::unique_ptr<FactoryCipher>>(sw_cipher);
            break;}
        case NID_chacha20:{
            auto *sw_cipher = new SwChaCha20();
            cipher = static_cast<std::unique_ptr<FactoryCipher>>(sw_cipher);
            break;}
        default:
            break;
    }
    return cipher;
}

std::unique_ptr<FactoryDigest> EngineFactory::GetDigest(int nid) noexcept 
{
    std::unique_ptr<FactoryDigest> digest {nullptr};
    switch(nid)
    {
        case NID_sha256:
           {auto *sw_digest = new SwSha256();
            digest = static_cast<std::unique_ptr<FactoryDigest>>(sw_digest);
            break;}
        case NID_sha384:
            {auto *sw_digest = new SwSha384();
            digest = static_cast<std::unique_ptr<FactoryDigest>>(sw_digest);
            break;}
        default:
            break;
    }
    return digest;
}


} // namespace SoftwareImpl
} // namespace Factory
