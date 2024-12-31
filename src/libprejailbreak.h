#ifndef LIBPREJAILBREAK_H
#define LIBPREJAILBREAK_H

#include "offsets.h"

#include <stdint.h>
#include <stdlib.h>

struct KernelPrimitives {
    uint8_t (*kread8)(uint64_t);
    uint16_t (*kread16)(uint64_t);
    uint32_t (*kread32)(uint64_t);
    uint64_t (*kread64)(uint64_t);
    int (*kreadbuf)(uint64_t, void *, size_t);

    int (*kwrite8)(uint64_t, uint8_t);
    int (*kwrite16)(uint64_t, uint16_t);
    int (*kwrite32)(uint64_t, uint32_t);
    int (*kwrite64)(uint64_t, uint64_t);
    int (*kwritebuf)(uint64_t, void *, size_t);

    uint64_t (*kalloc)(size_t);
    void (*kfree)(uint64_t, size_t);
};
extern struct KernelPrimitives gPrimitives;

struct GlobalInfo {
    struct ProcessInfo {
        uint64_t proc;
        uint64_t task;
        uint64_t ucred;
        uint64_t vm_map;
        uint64_t pmap;
    } processInfo;

    struct KernelInfo {
        uint64_t proc;
        uint64_t task;
        uint64_t ucred;
        uint64_t vm_map;
        uint64_t pmap;
        uint64_t slide;
    } kernelInfo;
};
extern struct GlobalInfo gGlobalInfo;

#define pinfo(x) (gGlobalInfo.processInfo.x)
#define kinfo(x) (gGlobalInfo.kernelInfo.x)
#define kslide(x) (x + kinfo(slide))

uint64_t proc_self(void);
uint64_t task_self(void);
uint64_t ucred_self(void);
uint64_t vm_map_self(void);
uint64_t pmap_self(void);

#define koffsetof(type, member) (offsets_find(#type "." #member, gOffsets.type.member))

uint8_t kread8(uint64_t va);
uint16_t kread16(uint64_t va);
uint32_t kread32(uint64_t va);
uint64_t kread64(uint64_t va);
uint64_t kread_ptr(uint64_t va);
int kwrite8(uint64_t va, uint8_t val);
int kwrite16(uint64_t va, uint16_t val);
int kwrite32(uint64_t va, uint32_t val);
int kwrite64(uint64_t va, uint64_t val);
int kreadbuf(uint64_t va, void *buffer, size_t size);
int kwritebuf(uint64_t va, void *buffer, size_t size);

uint64_t kalloc(size_t size);
void kfree(uint64_t va, size_t size);

#endif // LIBPREJAILBREAK_H