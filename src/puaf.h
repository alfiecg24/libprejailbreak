#ifndef LIBPREJAILBREAK_PUAF_H
#define LIBPREJAILBREAK_PUAF_H

#include <stdint.h>
#include <stdbool.h>

#define pages(num) ((num) * (vm_kernel_page_size))

#define VMNE_SIZE (pages(2) + 1)
#define VME_SIZE (pages(2))
#define VME_OFFSET (pages(1))

/*
* @brief Trigger the PhysPuppet physical use-after-free.
* @param[in] nPages
* @param[out] puafPages
*/
void physpuppet_run(int nPages, uint64_t puafPages[]);

/*
* @brief Deallocate all PUAF pages except the one being used for kernel read/write.
* @param[in] nPages
* @param[in] puafPages
* @param[in] puafPage
*/
void physpuppet_deinit(int nPages, uint64_t puafPages[], uint64_t puafPage);

/*
* @brief Initialise the copy object used to check if we have enough freed pages.
*/
void copy_init(void);

/*
* @brief Deinitialise the copy object.
*/
void copy_deinit(void);

/*
* @brief Check if a given array of PUAF pages has a high enough proportion of freed pages for exploitation.
* @param[in] nPages
* @param[in] puafPages
*/
bool puaf_check_free_pages(int nPages, uint64_t puafPages[]);

/*
* @brief Trick the PPL's page allocator into adding a large number of pages to the PPL free page
*        list, preventing the "page still has mappings panic" when a PUAF page gets used by the PPL.
*/
void puaf_fill_ppl_free_list(void);


#endif // LIBPREJAILBREAK_PUAF_H