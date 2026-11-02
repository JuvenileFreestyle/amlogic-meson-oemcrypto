/* SPDX-License-Identifier: ((GPL-2.0+ WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Amlogic Meson Secure Memory (SecMem) UAPI Header
 *
 * Provides userspace ioctl interface and DMA-BUF definitions for allocating
 * hardware-firewalled secure memory buffers used by OP-TEE, Widevine L1,
 * and secure hardware video decoders (VDEC).
 *
 * Author: JuvenileFreestyle <JuvenileFreestyle@users.noreply.github.com>
 */

#ifndef _UAPI_LINUX_MESON_SECMEM_H
#define _UAPI_LINUX_MESON_SECMEM_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define MESON_SECMEM_MAGIC 'S'

/* Allocation flags */
#define MESON_SECMEM_FLAG_CONTIGUOUS    (1 << 0)
#define MESON_SECMEM_FLAG_PROTECTED     (1 << 1) /* Locked by TrustZone DMC firewall */
#define MESON_SECMEM_FLAG_NO_CPU_ACCESS (1 << 2) /* mmap will return -EPERM */

/**
 * struct meson_secmem_alloc_data - Request to allocate a secure buffer
 * @size:       Size of the buffer in bytes (page-aligned)
 * @flags:      Allocation flags (MESON_SECMEM_FLAG_*)
 * @fd:         Output DMA-BUF file descriptor returned to userspace
 * @phys_addr:  Output physical base address (for privileged callers, else 0)
 * @reserved:   Reserved for future extension, must be 0
 */
struct meson_secmem_alloc_data {
	__u64 size;
	__u32 flags;
	__s32 fd;
	__u64 phys_addr;
	__u64 reserved[2];
};

/**
 * struct meson_secmem_lock_data - Configure TrustZone DMC memory firewall
 * @phys_addr:  Physical starting address
 * @size:       Size in bytes
 * @session_id: OP-TEE / TrustZone session ID
 * @status:     Return status from ARM SMC call
 */
struct meson_secmem_lock_data {
	__u64 phys_addr;
	__u64 size;
	__u32 session_id;
	__u32 status;
};

/* IOCTL Command Definitions */
#define MESON_SECMEM_IOC_ALLOC \
	_IOWR(MESON_SECMEM_MAGIC, 0x01, struct meson_secmem_alloc_data)

#define MESON_SECMEM_IOC_LOCK \
	_IOWR(MESON_SECMEM_MAGIC, 0x02, struct meson_secmem_lock_data)

#define MESON_SECMEM_IOC_UNLOCK \
	_IOWR(MESON_SECMEM_MAGIC, 0x03, struct meson_secmem_lock_data)

#define MESON_SECMEM_IOC_GET_PHYS \
	_IOWR(MESON_SECMEM_MAGIC, 0x04, struct meson_secmem_alloc_data)

#endif /* _UAPI_LINUX_MESON_SECMEM_H */
