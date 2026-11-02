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

#ifndef OEMCRYPTO_H_
#define OEMCRYPTO_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum OEMCryptoResult {
    OEMCrypto_SUCCESS = 0,
    OEMCrypto_ERROR_INIT_FAILED = 1,
    OEMCrypto_ERROR_TERMINATE_FAILED = 2,
    OEMCrypto_ERROR_OPEN_FAILURE = 3,
    OEMCrypto_ERROR_CLOSE_FAILURE = 4,
    OEMCrypto_ERROR_ENTER_SECURE_PLAYBACK_FAILED = 5,
    OEMCrypto_ERROR_EXIT_SECURE_PLAYBACK_FAILED = 6,
    OEMCrypto_ERROR_SHORT_BUFFER = 7,
    OEMCrypto_ERROR_NO_DEVICE_KEY = 8,
    OEMCrypto_ERROR_NO_ASSET_KEY = 9,
    OEMCrypto_ERROR_KEYBOX_INVALID = 10,
    OEMCrypto_ERROR_NO_KEYDATA = 11,
    OEMCrypto_ERROR_NO_CW = 12,
    OEMCrypto_ERROR_DECRYPT_FAILED = 13,
    OEMCrypto_ERROR_WRITE_KEYBOX = 14,
    OEMCrypto_ERROR_WRAP_KEYBOX = 15,
    OEMCrypto_ERROR_BAD_HASH = 16,
    OEMCrypto_ERROR_INSUFFICIENT_RESOURCES = 17,
    OEMCrypto_ERROR_SIGNATURE_FAILURE = 18,
    OEMCrypto_ERROR_TOO_MANY_SESSIONS = 19,
    OEMCrypto_ERROR_INVALID_SESSION = 20,
    OEMCrypto_ERROR_INVALID_CONTEXT = 21,
    OEMCrypto_ERROR_UNKNOWN_FAILURE = 22,
    OEMCrypto_ERROR_SECURE_BUFFER_REQUIRED = 23,
    OEMCrypto_ERROR_NOT_IMPLEMENTED = 24,
    OEMCrypto_ERROR_SESSION_LOST_STATE = 25,
    OEMCrypto_ERROR_SYSTEM_INVALIDATED = 26,
    OEMCrypto_WARNING_NEED_KEYSTATUS_CHECK = 27
} OEMCryptoResult;

typedef uint32_t OEMCrypto_SESSION;

typedef enum OEMCrypto_BufferType {
    OEMCrypto_BufferType_Clear = 0,
    OEMCrypto_BufferType_Secure = 1,
    OEMCrypto_BufferType_Direct = 2
} OEMCrypto_BufferType;

typedef struct {
    OEMCrypto_BufferType type;
    union {
        struct {
            uint8_t* address;
            size_t max_length;
        } clear;
        struct {
            void* handle;
            size_t max_length;
            size_t offset;
        } secure;
        struct {
            bool is_video;
            void* buffer;
        } direct;
    } buffer;
} OEMCrypto_DestBufferDesc;

typedef enum OEMCrypto_Algorithm {
    OEMCrypto_AES_CBC_128_NO_PADDING = 0,
    OEMCrypto_HMAC_SHA256 = 1,
    OEMCrypto_AES_CTR_128 = 2
} OEMCrypto_Algorithm;

typedef enum OEMCrypto_CipherMode {
    OEMCrypto_CipherMode_CTR = 0,
    OEMCrypto_CipherMode_CBC = 1
} OEMCrypto_CipherMode;

typedef enum OEMCrypto_LicenseType {
    OEMCrypto_ContentLicense = 0,
    OEMCrypto_EntitlementLicense = 1
} OEMCrypto_LicenseType;

/* Core OEMCrypto API functions */
OEMCryptoResult OEMCrypto_Initialize(void);
OEMCryptoResult OEMCrypto_Terminate(void);
OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session);
OEMCryptoResult OEMCrypto_CloseSession(OEMCrypto_SESSION session);
uint32_t OEMCrypto_APIVersion(void);
const char* OEMCrypto_SecurityLevel(void);
OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID, size_t* idLength);
OEMCryptoResult OEMCrypto_GetRandom(uint8_t* randomData, size_t dataLength);

OEMCryptoResult OEMCrypto_DecryptCENC(
    OEMCrypto_SESSION session,
    const uint8_t* data_addr,
    size_t data_length,
    bool is_encrypted,
    const uint8_t* iv,
    size_t block_offset,
    const OEMCrypto_DestBufferDesc* out_buffer,
    const uint8_t* subsamples,
    size_t subsample_count);

OEMCryptoResult OEMCrypto_CopyBuffer(
    OEMCrypto_SESSION session,
    const uint8_t* data_addr,
    size_t data_length,
    const OEMCrypto_DestBufferDesc* out_buffer,
    uint8_t subsample_flags);

#ifdef __cplusplus
}
#endif

#endif /* OEMCRYPTO_H_ */
