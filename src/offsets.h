#ifndef LIBPREJAILBREAK_OFFSETS_H
#define LIBPREJAILBREAK_OFFSETS_H

#include <stdint.h>
#include <stdbool.h>

struct KernelOffsets {
    int major, minor, patch;
    bool isArm64e;

    struct {
        uint64_t next;
        uint64_t prev;
        uint64_t pid;
        uint64_t task;
        uint64_t ucred;
        uint64_t fd;
        uint64_t csflags;
    } proc;

    struct {
        uint64_t ref_count;
        uint64_t active;
        uint64_t message_app_suspended;
        uint64_t vm_map;
        uint64_t itk_self;
        uint64_t itk_space;
        uint64_t bsd_info;
        uint64_t flags;
    } task;

    struct {
        uint64_t pmap;
    } vm_map;
    
    struct {
        uint64_t tte;
        uint64_t ttep;
    } pmap;

    struct {
        uint64_t table;
    } ipc_space;

    struct {
        uint64_t kobject;
        uint64_t receiver;
        uint64_t ikmq_base;
        uint64_t references;
        uint64_t srights;
    } ipc_port;

    struct {
        uint64_t uid;
        uint64_t ruid;
        uint64_t svuid;
        uint64_t rgid;
        uint64_t svgid;
        uint64_t groups;
        uint64_t label;
    } ucred;

    struct {
        uint64_t ubcinfo;
        uint64_t specinfo;
        uint64_t name;
        uint64_t parent;
        uint64_t mount;
        uint64_t data;
        uint64_t nclinks;
        uint64_t holdcount;
    } vnode;

    struct {
        uint64_t csblobs;
    } ubcinfo;

    struct {
        uint64_t cputype;
        uint64_t flags;
        uint64_t signer_type;
        uint64_t platform_binary;
    } csblob;
};
extern struct KernelOffsets gOffsets;

/*
* @brief Check an offset to warn the user if they haven't initialised offsets.
* @param[in] name
* @param[in] value
* @returns offset or -1 (if there is no offset available).
*/
uint64_t offsets_find(const char *name, uint64_t value);

/*
* @brief Initialise offsets for the device and version being used.
*/
void offsets_init(void);

#define MAJOR(x) (x + 6) // iOS major version to Darwin major version

#endif // LIBPREJAILBREAK_OFFSETS_H