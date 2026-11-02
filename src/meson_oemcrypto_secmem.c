/*
 * Copyright (C) 2026 JuvenileFreestyle <JuvenileFreestyle@users.noreply.github.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "include/meson_oemcrypto_secmem.h"
#include "include/meson_secmem_uapi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

static int g_secmem_fd = -1;

int meson_secmem_init(void)
{
    if (g_secmem_fd >= 0)
        return 0;

    g_secmem_fd = open("/dev/meson_secmem", O_RDWR | O_CLOEXEC);
    if (g_secmem_fd < 0) {
        /* Fallback check for alternate node path */
        g_secmem_fd = open("/dev/secmem", O_RDWR | O_CLOEXEC);
    }

    if (g_secmem_fd < 0) {
        fprintf(stderr, "[OEMCrypto-SecMem] Failed to open secmem device: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

void meson_secmem_terminate(void)
{
    if (g_secmem_fd >= 0) {
        close(g_secmem_fd);
        g_secmem_fd = -1;
    }
}

int meson_secmem_alloc(size_t size, int *out_fd, uint64_t *out_paddr)
{
    struct meson_secmem_alloc_data req;

    if (g_secmem_fd < 0 && meson_secmem_init() < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.size = size;
    req.flags = MESON_SECMEM_FLAG_CONTIGUOUS | 
                MESON_SECMEM_FLAG_PROTECTED | 
                MESON_SECMEM_FLAG_NO_CPU_ACCESS;

    if (ioctl(g_secmem_fd, MESON_SECMEM_IOC_ALLOC, &req) < 0) {
        fprintf(stderr, "[OEMCrypto-SecMem] Alloc ioctl failed: %s\n", strerror(errno));
        return -1;
    }

    if (out_fd)
        *out_fd = req.fd;
    if (out_paddr)
        *out_paddr = req.phys_addr;

    return 0;
}

int meson_secmem_lock(uint64_t paddr, size_t size, uint32_t session_id)
{
    struct meson_secmem_lock_data req;

    if (g_secmem_fd < 0 && meson_secmem_init() < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.phys_addr = paddr;
    req.size = size;
    req.session_id = session_id;

    if (ioctl(g_secmem_fd, MESON_SECMEM_IOC_LOCK, &req) < 0) {
        fprintf(stderr, "[OEMCrypto-SecMem] Lock ioctl failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int meson_secmem_unlock(uint64_t paddr, size_t size, uint32_t session_id)
{
    struct meson_secmem_lock_data req;

    if (g_secmem_fd < 0 && meson_secmem_init() < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.phys_addr = paddr;
    req.size = size;
    req.session_id = session_id;

    if (ioctl(g_secmem_fd, MESON_SECMEM_IOC_UNLOCK, &req) < 0) {
        fprintf(stderr, "[OEMCrypto-SecMem] Unlock ioctl failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
