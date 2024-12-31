#include "escalation.h"
#include "libprejailbreak.h"
#include "utils.h"
#include "codesigning.h"

void proc_fix_setuid_setgid(uint64_t proc) {
  uint64_t ucred = kread_ptr(proc + koffsetof(proc, ucred));
  kwrite32(ucred + koffsetof(ucred, svuid), 0);
  kwrite32(ucred + koffsetof(ucred, uid), 0);
  kwrite32(ucred + koffsetof(ucred, svgid), 0);
  kwrite32(ucred + koffsetof(ucred, groups), 0);
}

void proc_set_mac_label(uint64_t proc, int slot, uint64_t value) {
  uint64_t ucred = kread_ptr(proc + koffsetof(proc, ucred));
  uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
  kwrite64(label + ((slot + 1) * sizeof(uint64_t)), value);
}

uint64_t proc_get_mac_label(uint64_t proc, int slot) {
  uint64_t ucred = kread_ptr(proc + koffsetof(proc, ucred));
  uint64_t label = kread64(ucred + koffsetof(ucred, label));
  return kread64(label + ((slot + 1) * sizeof(uint64_t)));
}

void proc_update_csflags(uint64_t proc) {
  proc_add_csflags(proc, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_VALID | CS_INVALID_ALLOWED);
  proc_remove_csflags(proc, CS_RESTRICT | CS_HARD | CS_KILL | CS_FORCED_LV | CS_ENFORCEMENT | CS_REQUIRE_LV);
}