#ifndef ENGINE_IMPL_FACTORY_FACTORY_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_HPP

#include <cstdint>
#include <openssl/evp.h>
#include <memory>
#include <factory/factory_cipher.hpp>
#include <factory/factory_digest.hpp>


namespace Factory {

/**
 * Abstract class defining a factory interface for OpenSSL engines.
 */
class Factory {
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
};

} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_FACTORY_HPP
