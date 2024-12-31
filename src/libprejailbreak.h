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

/*
* @brief Retrieve the address of the process's proc structure.
* @returns Kernel address of the proc structure, or zero if not set yet.
*/
uint64_t proc_self(void);

/*
* @brief Retrieve the address of the process's task structure.
* @returns Kernel address of the task structure, or zero if not set yet.
*/
uint64_t task_self(void);

/*
* @brief Retrieve the address of the process's ucred structure.
* @returns Kernel address of the ucred structure, or zero if not set yet.
*/
uint64_t ucred_self(void);

/*
* @brief Retrieve the address of the process's vm_map structure.
* @returns Kernel address of the vm_map structure, or zero if not set yet.
*/
uint64_t vm_map_self(void);

/*
* @brief Retrieve the address of the process's pmap structure.
* @returns Kernel address of the pmap structure, or zero if not set yet.
*/
uint64_t pmap_self(void);

/*
* @brief Read an 8-bit value at a kernel memory address.
* @param[in] va
* @returns Value at that address, zero if primitive not setup.
*/
uint8_t kread8(uint64_t va);

/*
* @brief Read a 16-bit value at a kernel memory address.
* @param[in] va
* @returns Value at that address, zero if primitive not setup.
*/
uint16_t kread16(uint64_t va);

/*
* @brief Read a 32-bit value at a kernel memory address.
* @param[in] va
* @returns Value at that address, zero if primitive not setup.
*/
uint32_t kread32(uint64_t va);

/*
* @brief Read a 64-bit value at a kernel memory address.
* @param[in] va
* @returns Value at that address, zero if primitive not setup.
*/
uint64_t kread64(uint64_t va);

/*
* @brief Read a 64-bit pointer at a kernel memory address and remove the PAC if present.
* @param[in] va
* @returns Value at that address, zero if primitive not setup.
*/
uint64_t kread_ptr(uint64_t va);

/*
* @brief Write an 8-bit value to a kernel memory address.
* @param[in] va
* @param[in] value
* @returns Error code
*/
int kwrite8(uint64_t va, uint8_t val);

/*
* @brief Write a 16-bit value to a kernel memory address.
* @param[in] va
* @param[in] value
* @returns Error code
*/
int kwrite16(uint64_t va, uint16_t val);

/*
* @brief Write a 32-bit value to a kernel memory address.
* @param[in] va
* @param[in] value
* @returns Error code
*/
int kwrite32(uint64_t va, uint32_t val);

/*
* @brief Write a 64-bit value to a kernel memory address.
* @param[in] va
* @param[in] value
* @returns Error code
*/
int kwrite64(uint64_t va, uint64_t val);

/*
* @brief Read a buffer of the specified size from a kernel memory address.
* @param[in] va
* @param[in] buffer
* @param[in] size
* @returns Error code
*/
int kreadbuf(uint64_t va, void *buffer, size_t size);

/*
* @brief Copy a buffer of the specified size to a kernel memory address.
* @param[in] va
* @param[in] buffer
* @param[in] size
* @returns Error code
*/
int kwritebuf(uint64_t va, void *buffer, size_t size);

/*
* @brief Allocate a region of kernel memory.
* @param[in] size
* @returns Address of the allocation
*/
uint64_t kalloc(size_t size);

/*
* @brief Free a region of kernel memory.
* @param[in] va
* @param[in] size
* @returns Address of the allocation
*/
void kfree(uint64_t va, size_t size);

#define pinfo(x) (gGlobalInfo.processInfo.x)
#define kinfo(x) (gGlobalInfo.kernelInfo.x)
#define kslide(x) (x + kinfo(slide))
#define koffsetof(type, member) (offsets_find(#type "." #member, gOffsets.type.member))

#endif // LIBPREJAILBREAK_H