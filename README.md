# libprejailbreak

A universal library allowing you to gain kernel read/write primitives and escalate privileges on devices running iOS 12 - iOS 14. libprejailbreak offers the required functionality needed for a jailbreak and can be used as a foundation for one.

## Kernel exploit
The kernel exploit supports all devices running iOS 12 to iOS 14. The exploit is based off of the PhysPuppet physical use-after-free vulnerability first exploited with kfd. It is extremely reliable, causing very few post-exploit panics, as well as being quite quick (rarely exceeding 100 milliseconds, but sometimes even less than 10).

The exploit makes use of IOSurface objects to read from and write to kernel memory. This does not permanently overwrite any values in kernel memory, with the original ones being restored after performing a read or write operation. As such, it is completely stable and requires no cleanup.

To run the kernel exploit, call `kernel_rw_init()`. To deinitialise the exploit (e.g. when you're finished or when tfp0 is setup), call `kernel_rw_deinit()`.

## tfp0
On iOS 12 and iOS 13, the exploit will create a fake task port for the kernel task, which allows you to read from and write to kernel memory without relying on exploit primitives. This is a standard practice for any jailbreak on these versions, so it is available from libprejailbreak. You can initialise tfp0 by calling `tfp0_init()`.

## Privilege escalation
With libprejailbreak, you can easily unsandbox your process and escalate to root. Unsandboxing is done by patching the AMFI slot in the process’s MAC label to replace it with a NULL pointer. This effectively removes all sandbox restrictions for the process. Escalation to root is done by patching the `svuid` value in the process’s ucred structure to allow you to call `setuid(0)`.

* `proc_fix_setuid_setgid()` - fixes `setuid()`
* `proc_update_csflags()` - adds CS_PLATFORM_BINARY among other beneficial CS flags
* `proc_set_mac_label()` - removes sandboxing restrictions from the process

## Future plans
In the future, I would like to incorporate the following functionality into this library:
* An additional exploit based off of the landa vulnerability, adding support for all of iOS 15 and most of iOS 16.
* Physical address mapping primitives for all versions.
* An implementation of the dmaFail PPL bypass to allow privilege escalation on iOS 15 and iOS 16 for arm64e devices.
* Kernel call primitives for arm64 devices.
* Root filesystem remount capabilities on iOS 14 and below.
* Physical read/write primitives via page tables on iOS 14 and above.