#ifndef ENGINE_IMPL_SRC_RANDOM_SW_RANDOM_HPP
#define ENGINE_IMPL_SRC_RANDOM_SW_RANDOM_HPP

#include <factory/factory_random.hpp>

namespace Factory {
namespace SoftwareImpl {
    

class SwRandom : public Factory::FactoryRandom {
public:

  SwRandom() = default;
  SwRandom(SwRandom &) = delete;
  SwRandom(SwRandom &&) = delete;
  SwRandom &operator=(SwRandom &) = delete;
  SwRandom &operator=(SwRandom &&) = delete;
  ~SwRandom() = default;

  static void Cleanup() noexcept override;
  static int RandomBytes(unsigned char *buf, int num) noexcept override;
  static int RandomStatus() noexcept override;
  static int SetSeed() noexcept override;

};

} // namespace SoftwareImpl
} // namespace Factory


#endif // ENGINE_IMPL_SRC_RANDOM_SW_RANDOM_HPP
