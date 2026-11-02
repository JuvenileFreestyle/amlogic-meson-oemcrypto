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

#ifndef MESON_OEMCRYPTO_SECMEM_H_
#define MESON_OEMCRYPTO_SECMEM_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int meson_secmem_init(void);
void meson_secmem_terminate(void);

int meson_secmem_alloc(size_t size, int *out_fd, uint64_t *out_paddr);
int meson_secmem_lock(uint64_t paddr, size_t size, uint32_t session_id);
int meson_secmem_unlock(uint64_t paddr, size_t size, uint32_t session_id);

#ifdef __cplusplus
}
#endif

#endif /* MESON_OEMCRYPTO_SECMEM_H_ */
