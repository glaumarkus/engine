#ifndef ENGINE_IMPL_FACTORY_FACTORY_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_HPP

#include <cstdint>
#include <openssl/evp.h>
#include <memory>
#include <factory/factory_cipher.hpp>
#include <factory/factory_digest.hpp>
#include <factory/factory_ec.hpp>
#include <factory/factory_pubkey.hpp>
#include <factory/factory_pkey.hpp>


namespace Factory {

/**
 * Abstract class defining a factory interface for OpenSSL engines.
 */
class EngineFactory {
public:

  /**
   * Get size of a Factory instance to be stored at the host application
   *
   * \return Fixed size of the derived factory class implementation.
   */
  virtual std::size_t Size() const noexcept = 0;

  /**
   * Initializes the factory with the given buffer and size.
   *
   * \param buf A pointer to the buffer.
   * \return 1 on success, 0 otherwise.
   */
  virtual int Init() noexcept = 0;

  /**
   * Finalizes the factory.
   *
   * \return 1 on success, 0 otherwise.
   */
  virtual int Finish() noexcept = 0;

  /**
   * Sends a control command to the factory.
   *
   * \param e The engine.
   * \param cmd The command to execute.
   * \param i The command argument.
   * \param p A pointer to additional data.
   * \param f A callback function.
   * \return The result of the command.
   */
  virtual int CtrlCmd(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) noexcept = 0;

  /**
   * Get the default cipher that is registered for the provided nid.
   *
   * \param nid The identifer of the requested algorithm.
   * \return An instance of the cipher algorithm or nullptr on failure.
   */
  virtual std::unique_ptr<FactoryCipher> GetCipher(int nid) noexcept = 0;

  
  /**
   * Get the default digest that is registered for the provided nid.
   *
   * \param nid The identifer of the requested algorithm.
   * \return An instance of the digest algorithm or nullptr on failure.
   */
  virtual std::unique_ptr<FactoryDigest> GetDigest(int nid) noexcept = 0;

  /**
   * Get an instance of the specified curve that is registered for the provided nid.
   *
   * \param nid The identifer of the requested curve.
   * \return An instance of the EC algorithm or nullptr on failure.
   */
  virtual std::unique_ptr<FactoryEC> GetEC(int nid) noexcept = 0;

  virtual std::unique_ptr<FactoryPrivKey> GetPrivateKeyLoader() noexcept = 0;
  virtual std::unique_ptr<FactoryPubKey> GetPublicKeyLoader() noexcept = 0;
};

} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_FACTORY_HPP
