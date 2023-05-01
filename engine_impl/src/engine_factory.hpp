#ifndef ENGINE_IMPL_FACTORY_SRC_ENGINE_FACTORY_HPP
#define ENGINE_IMPL_FACTORY_SRC_ENGINE_FACTORY_HPP

#include <vector>

#include <openssl/x509.h>

#include <factory/factory.hpp>
#include "digests/sw_digest_sha256.hpp"
#include "digests/sw_digest_sha384.hpp"
#include "ciphers/sw_cipher_aes256cbc.hpp"
#include "ciphers/sw_cipher_aes256gcm.hpp"
#include "ciphers/sw_cipher_chacha20.hpp"
#include "asym/sw_ec.hpp"
#include "asym/sw_pkey.hpp"
#include "asym/sw_pubkey.hpp"

namespace Factory {
namespace SoftwareImpl {

class EngineFactory : public Factory::EngineFactory
{
public:

    explicit EngineFactory() = default;
    EngineFactory(EngineFactory &) = delete;
    EngineFactory(EngineFactory &&) = delete;
    EngineFactory &operator=(EngineFactory &) = delete;
    EngineFactory &operator=(EngineFactory &&) = delete;
    ~EngineFactory() = default;

    std::size_t Size() const noexcept override;
    int Init() noexcept override;
    int Finish() noexcept override;
    int CtrlCmd(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) noexcept override;

    std::unique_ptr<FactoryCipher> GetCipher(int nid) noexcept override;
    std::unique_ptr<FactoryDigest> GetDigest(int nid) noexcept override;
    std::unique_ptr<FactoryEC> GetEC(int nid) noexcept override;
    
    std::unique_ptr<FactoryPrivKey> GetPrivateKeyLoader() noexcept override;
    std::unique_ptr<FactoryPubKey> GetPublicKeyLoader() noexcept override;

private:

    int ParseCmdString(void *ptr) noexcept;
    int LoadCertFromString(void *cert_ptr) noexcept;

};


} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_ENGINE_FACTORY_HPP
