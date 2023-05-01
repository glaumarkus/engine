#include "src/engine_factory.hpp"

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <string>

// Tests
class Test_EC : public ::testing::Test {
protected:
  void SetUp() override {}
};



TEST_F(Test_EC, TestAes256Gcm) {

    auto factory = Factory::SoftwareImpl::EngineFactory();
    auto ec = factory.GetEC(NID_secp384r1);

    EXPECT_NE(ec, nullptr);
}