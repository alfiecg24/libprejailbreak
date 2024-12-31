#ifndef LIBPREJAILBREAK_ESCALATE_H
#define LIBPREJAILBREAK_ESCALATE_H

#include <stdint.h>

/*
* @brief Fix setuid() for a proc structure and allow it to escalate to root.
* @param[in] proc
*/
void proc_fix_setuid_setgid(uint64_t proc);

/*
* @brief Set a value in the proc's MAC label array
* @param[in] proc
* @param[in] slot
* @param[in] value
*/
void proc_set_mac_label(uint64_t proc, int slot, uint64_t value);

/*
* @brief Retrieve a value from the proc's MAC label array
* @param[in] proc
* @param[in] slot
* @returns Value in the slot.
*/
uint64_t proc_get_mac_label(uint64_t proc, int slot);

/*
* @brief Add all beneficial CS flags and remove any unnecessary ones.
* @param[in] proc
*/
void proc_update_csflags(uint64_t proc);
#endif // LIBPREJAILBREAK_ESCALATE_H