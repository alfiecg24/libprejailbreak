#include "utils.h"
#include "offsets.h"
#include "libprejailbreak.h"

#define IPC_ENTRY_SIZE (0x18)

uint64_t proc_find(pid_t pid) {
    uint64_t proc = kinfo(proc);
    while (proc >= 0xffffffe000000000) {
      uint32_t curPid = kread32(proc + koffsetof(proc, pid));
      if (curPid == pid)
        return proc;
      proc = kread64(proc + koffsetof(proc, prev));
    }
    return proc;
}

uint64_t task_get_ipc_port(uint64_t task, mach_port_t port) {
  uint64_t itk_space = kread64(task + koffsetof(task, itk_space));
  uint64_t table = kread64(itk_space + koffsetof(ipc_space, table));
  uint64_t entry = kread64(table + (IPC_ENTRY_SIZE * (uint64_t)(port >> 8)));
  return entry;
}

uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port) {
  uint64_t entry = task_get_ipc_port(task, port);
  uint32_t bits = kread32(entry);
  if (gOffsets.major >= MAJOR(14) && (bits & 0x400) != 0) {
    uint64_t label = kread64(entry + koffsetof(ipc_port, kobject));
    return kread64(label + 0x8);
  }

  return kread64(entry + koffsetof(ipc_port, kobject));
}

void proc_remove_csflags(uint64_t proc, uint32_t flags) {
  uint32_t currentFlags = kread32(proc + koffsetof(proc, csflags));
  kwrite32(proc + koffsetof(proc, csflags), currentFlags & ~flags);
}

void proc_add_csflags(uint64_t proc, uint32_t flags) {
  uint32_t currentFlags = kread32(proc + koffsetof(proc, csflags));
  kwrite32(proc + koffsetof(proc, csflags), currentFlags | flags);
}