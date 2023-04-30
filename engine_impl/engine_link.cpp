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

int parse_cmd_string(void *p) {
  // reinterpret as const char*
  const char *cmd_name = reinterpret_cast<const char *>(p);
  int ok = 0;
  // check if LOAD_CERT_CTRL is supported
  if (!std::strcmp(cmd_name, "LOAD_CERT_CTRL")) {
    ok = 1;
  }
  return ok;
}


/*
--> cast to this structure
*/
int load_certificate(void *cert) {

  int ok = 0;

  // structure to fill
  struct params {
    const char *cert_id;
    X509 *cert;
  };

  // cast to params
  params *p = static_cast<params *>(cert);

  // now load the certificate from string
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

int ctrl_cmd_string(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {

  printf("ctrl_cmd_string called\n");
  printf("Params: \n");
  printf("e: %p, cmd: %d, i: %ld, p: %p, f: %p\n", e, cmd, i, p, f);

  int ok = 0;
  switch (cmd) {
  case ENGINE_CTRL_SET_LOGSTREAM:
    // implement cert parsing
    ok = load_certificate(p);
    break;
  case ENGINE_CTRL_GET_CMD_FROM_NAME:
    ok = parse_cmd_string(p);
    break;
  default:
    ok = ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED;
    break;
  }

  return ok;
}