#ifndef LIBPREJAILBREAK_INFO_H
#define LIBPREJAILBREAK_INFO_H

#include <stdint.h>

/*
* @brief Finds relevant kernel structures and values.
*/
int info_init(uint64_t task);

#endif // LIBPREJAILBREAK_INFO_H