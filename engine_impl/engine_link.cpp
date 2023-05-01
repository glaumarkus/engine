#include "engine_link.h"
#include <cstring>
#include <iostream>
#include <openssl/engine.h>
#include "src/engine_factory.hpp"

enum class CmdStrings : int { kInitArgs = 200, kLoadCertCtrl = 201 };

void get_impl_size(size_t* size)
{
  *size = sizeof(Factory::SoftwareImpl::EngineFactory);
}

int init(engine_factory_instance* instance) { 
  int ok = 0;
  if (instance != nullptr)
  {
    auto *factory = new Factory::SoftwareImpl::EngineFactory();
    instance->instance = static_cast<void*>(factory);
    instance->size = sizeof(Factory::SoftwareImpl::EngineFactory);
    ok = 1;
  }
  return ok; }
  
int finish(engine_factory_instance* instance) {
  int ok = 0;
  // remove instance 
  if (instance->instance != nullptr)
  {
    // change pointer
    auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
    // delete
    delete factory;
    ok = 1;
  }
  else
  {
    ok = 1;
  }
  return ok; }

int ctrl_cmd_string(struct engine_factory_instance* instance, ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {

  int ok = 0;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    ok = factory->CtrlCmd(e, cmd, i, p, f);
  }

  return ok;
}