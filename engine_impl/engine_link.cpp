#include "engine_link.h"
#include <cstring>
#include <iostream>
#include <openssl/engine.h>

enum class CmdStrings : int { kInitArgs = 200, kLoadCertCtrl = 201 };

int init() { return 1; }
int finish() { return 1; }

int parse_cmd_string(void *p) {
  // reinterpret as const char*
  const char *cmd_name = reinterpret_cast<const char *>(p);

  int compare = std::strcmp(cmd_name, "LOAD_CERT_CTRL");
  if (compare == 0) {
    return 1;
  }
  return 0;
}

// ENGINE_ctrl_cmd(data->state.engine, cmd_name,
// 0, &params, NULL, 1))
// struct {
//     const char *cert_id;
//     X509 *cert;
//   } params;

int ctrl_cmd_string(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {

  int ok = 0;
  switch (cmd) {
  case ENGINE_CTRL_GET_CMD_FROM_NAME:
    ok = parse_cmd_string(p);
    break;
  default:
    break;
  }

  return ok;
}