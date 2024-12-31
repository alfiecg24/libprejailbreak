#include "libprejailbreak.h"

struct KernelPrimitives gPrimitives = { 0 };
struct GlobalInfo gGlobalInfo = { 0 };

uint64_t proc_self(void) {
    return pinfo(proc);
}

uint64_t task_self(void) {
    return pinfo(task);
}

uint64_t ucred_self(void) {
    return pinfo(ucred);
}

uint64_t vm_map_self(void) {
    return pinfo(vm_map);
}

uint64_t pmap_self(void) {
    return pinfo(pmap);
}

uint8_t kread8(uint64_t va) {
    if (!gPrimitives.kread8) return 0;
    return gPrimitives.kread8(va);
}

uint16_t kread16(uint64_t va) {
    if (!gPrimitives.kread16) return 0;
    return gPrimitives.kread16(va);
}

uint32_t kread32(uint64_t va) {
    if (!gPrimitives.kread32) return 0;
    return gPrimitives.kread32(va);
}

uint64_t kread64(uint64_t va) {
    if (!gPrimitives.kread64) return 0;
    return gPrimitives.kread64(va);
}

uint64_t kread_ptr(uint64_t va) {
    uint64_t ptr = kread64(va);
    return (ptr >> 55) & 1 ? ptr | 0xFFFFFF8000000000 : ptr;
}

int kreadbuf(uint64_t va, void *buffer, size_t size) {
    if (!gPrimitives.kreadbuf) return -1;
    return gPrimitives.kreadbuf(va, buffer, size);
}

int kwrite8(uint64_t va, uint8_t val) {
    if (!gPrimitives.kwrite8) return -1;
    return gPrimitives.kwrite8(va, val);
}

int kwrite16(uint64_t va, uint16_t val) {
    if (!gPrimitives.kwrite16) return -1;
    return gPrimitives.kwrite16(va, val);
}

int kwrite32(uint64_t va, uint32_t val) {
    if (!gPrimitives.kwrite32) return -1;
    return gPrimitives.kwrite32(va, val);
}

int kwrite64(uint64_t va, uint64_t val) {
    if (!gPrimitives.kwrite64) return -1;
    return gPrimitives.kwrite64(va, val);
}

int kwritebuf(uint64_t va, void *buffer, size_t size) {
    if (!gPrimitives.kwritebuf) return -1;
    return gPrimitives.kwritebuf(va, buffer, size);
}

uint64_t kalloc(size_t size) {
    if (!gPrimitives.kalloc) return 0;
    return gPrimitives.kalloc(size);
}

void kfree(uint64_t va, size_t size) {
    if (!gPrimitives.kfree) return;
    gPrimitives.kfree(va, size);
}