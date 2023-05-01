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

  void Cleanup() noexcept override;
  int RandomBytes(unsigned char *buf, int num) noexcept override;
  int RandomStatus() noexcept override;
  int SetSeed() noexcept override;

};

} // namespace SoftwareImpl
} // namespace Factory


#endif // ENGINE_IMPL_SRC_RANDOM_SW_RANDOM_HPP
