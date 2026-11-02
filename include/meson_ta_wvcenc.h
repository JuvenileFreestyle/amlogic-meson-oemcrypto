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

#ifndef MESON_TA_WVCENC_H_
#define MESON_TA_WVCENC_H_

#include <stdint.h>
#include <tee_client_api.h>

/* Widevine L1 OP-TEE Trusted Application UUID for Amlogic G12B / Raven */
static const TEEC_UUID TA_WVCENC_UUID = {
    0xe043cde0, 0x61d0, 0x11e5,
    { 0x9c, 0x26, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b }
};

/* TA Command Identifiers */
enum {
    TA_WVCENC_CMD_INITIALIZE                   = 1,
    TA_WVCENC_CMD_TERMINATE                    = 2,
    TA_WVCENC_CMD_OPEN_SESSION                 = 3,
    TA_WVCENC_CMD_CLOSE_SESSION                = 4,
    TA_WVCENC_CMD_GENERATE_DERIVEDKEYS         = 5,
    TA_WVCENC_CMD_GENERATE_NONCE               = 6,
    TA_WVCENC_CMD_LOADKEYS                     = 7,
    TA_WVCENC_CMD_REFRESHKEYS                  = 8,
    TA_WVCENC_CMD_SELECT_KEY                   = 9,
    TA_WVCENC_CMD_DECRYPTCENC                  = 10,
    TA_WVCENC_CMD_GENERIC_ENCRYPT              = 11,
    TA_WVCENC_CMD_GENERIC_DECRYPT              = 12,
    TA_WVCENC_CMD_GENERIC_SIGN                 = 13,
    TA_WVCENC_CMD_GENERIC_VERIFY               = 14,
    TA_WVCENC_CMD_GET_DEVICEID                 = 15,
    TA_WVCENC_CMD_GET_KEYDATA                  = 16,
    TA_WVCENC_CMD_GET_RANDOM                   = 17,
    TA_WVCENC_CMD_WRAP_KEYBOX                  = 18,
    TA_WVCENC_CMD_INSTALL_KEYBOX               = 19,
    TA_WVCENC_CMD_ISKEYBOX_VALID               = 20,
    TA_WVCENC_CMD_GET_HDCP_CAPABILITY          = 21,
    TA_WVCENC_CMD_GET_NUMBER_OF_OPEN_SESSIONS  = 22,
    TA_WVCENC_CMD_GET_MAX_NUMBER_OF_SESSIONS   = 23,
    TA_WVCENC_CMD_COPY_BUFFER                  = 24,
};

#endif /* MESON_TA_WVCENC_H_ */
