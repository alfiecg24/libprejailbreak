#ifndef LIBPREJAILBREAK_UTILS_H
#define LIBPREJAILBREAK_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>

/*
* @brief Search for the proc structure corresponding to the specified PID.
* @param[in] pid
* @returns Kernel address of the proc structure, or zero if not found.
*/
uint64_t proc_find(pid_t pid);

/*
* @brief Find the kernel address corresponding to the specified Mach port.
* @param[in] task
* @param[in] port
* @returns Kernel address of the port.
*/
uint64_t task_get_ipc_port(uint64_t task, mach_port_t port);

/*
* @brief Find the kernel address of the object corresponding to the specified Mach port.
* @param[in] task
* @param[in] port
* @returns Kernel address of the object.
*/
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

/*
* @brief Remove the specified flags from a proc's csflags.
* @param[in] proc
* @param[in] flags
*/
void proc_remove_csflags(uint64_t proc, uint32_t flags);

/*
* @brief Add the specified flags to a proc's csflags.
* @param[in] proc
* @param[in] flags
*/
void proc_add_csflags(uint64_t proc, uint32_t flags);


#endif // LIBPREJAILBREAK_UTILS_H