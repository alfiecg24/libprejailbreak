#ifndef LIBPREJAILBREAK_IOKIT_H
#define LIBPREJAILBREAK_IOKIT_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <device/device_types.h>
#include <mach/vm_map.h>

typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

#define IOSURFACE_MAGIC 0x1EA5CACE

/*
* @brief Initialises the IOSurface userclient for exploitation.
* @param[out] client
*/
void iosurface_init(io_connect_t *client);

/*
* @brief Initialises the IOSurface userclient for exploitation.
* @param[in] puafPages
*/
void iosurface_deinit(uint64_t *puafPages);

/*
* @brief Creates kernel read/write primitives using IOSurface objects.
* @param[in] client
* @param[in] puafPages
* @param[in] nPages
* @param[out] task_self
* @param[out] puafPage
* @returns error code.
*/
int iosurface_krw(io_connect_t client, uint64_t *puafPages, int nPages, uint64_t *task_self, uint64_t *puafPage);

/*
* @brief Read a 32-bit value at an arbitrary kernel address.
* @param[in] va
* @returns Value at the address
*/
uint32_t iosurface_kread32(uint64_t va);

/*
* @brief Read a 64-bit value at an arbitrary kernel address.
* @param[in] va
* @returns Value at the address
*/
uint64_t iosurface_kread64(uint64_t va);

/*
* @brief Write a 32-bit value at an arbitrary kernel address.
* @param[in] va
* @param[in] value
* @returns Error code.
*/
int iosurface_kwrite32(uint64_t va, uint32_t value);

/*
* @brief Write a 64-bit value at an arbitrary kernel address.
* @param[in] va
* @param[in] value
* @returns Error code.
*/
int iosurface_kwrite64(uint64_t va, uint64_t value);


/*
* @brief Read data from  an arbitrary kernel address into a userspace buffer.
* @param[in] va
* @param[in] buffer
* @param[in] size
* @returns Error code.
*/
int iosurface_kreadbuf(uint64_t addr, void *buffer, size_t size);

/*
* @brief Write data from a userspace buffer to an arbitrary kernel address.
* @param[in] va
* @param[in] buffer
* @param[in] size
* @returns Error code.
*/
int iosurface_kwritebuf(uint64_t addr, void *buffer, size_t size);

#endif // LIBPREJAILBREAK_IOKIT_H