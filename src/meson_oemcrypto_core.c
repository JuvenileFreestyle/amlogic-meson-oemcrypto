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

#include "include/OEMCrypto.h"
#include "include/meson_ta_wvcenc.h"
#include "include/meson_oemcrypto_secmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <tee_client_api.h>

#define OEMCRYPTO_API_VERSION 16
#define SECURITY_LEVEL_L1 "L1"

static pthread_mutex_t g_oemcrypto_lock = PTHREAD_MUTEX_INITIALIZER;
static TEEC_Context g_tee_ctx;
static TEEC_Session g_tee_session;
static bool g_tee_initialized = false;
static uint32_t g_active_sessions = 0;

OEMCryptoResult OEMCrypto_Initialize(void)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    pthread_mutex_lock(&g_oemcrypto_lock);

    if (g_tee_initialized) {
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_SUCCESS;
    }

    res = TEEC_InitializeContext(NULL, &g_tee_ctx);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] TEEC_InitializeContext failed: 0x%08x\n", res);
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_INIT_FAILED;
    }

    memset(&op, 0, sizeof(op));
    res = TEEC_OpenSession(&g_tee_ctx, &g_tee_session, &TA_WVCENC_UUID,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] TEEC_OpenSession to Widevine TA failed: 0x%08x (origin 0x%x)\n",
                res, err_origin);
        TEEC_FinalizeContext(&g_tee_ctx);
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_INIT_FAILED;
    }

    /* Dispatch TA initialization */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_INITIALIZE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] TA_WVCENC_CMD_INITIALIZE failed: 0x%08x\n", res);
        TEEC_CloseSession(&g_tee_session);
        TEEC_FinalizeContext(&g_tee_ctx);
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_INIT_FAILED;
    }

    meson_secmem_init();

    g_tee_initialized = true;
    pthread_mutex_unlock(&g_oemcrypto_lock);

    printf("[OEMCrypto] Amlogic Meson Widevine L1 initialized successfully\n");
    return OEMCrypto_SUCCESS;
}

OEMCryptoResult OEMCrypto_Terminate(void)
{
    TEEC_Operation op;
    uint32_t err_origin;

    pthread_mutex_lock(&g_oemcrypto_lock);

    if (!g_tee_initialized) {
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_SUCCESS;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_TERMINATE, &op, &err_origin);

    meson_secmem_terminate();

    TEEC_CloseSession(&g_tee_session);
    TEEC_FinalizeContext(&g_tee_ctx);

    g_tee_initialized = false;
    pthread_mutex_unlock(&g_oemcrypto_lock);

    return OEMCrypto_SUCCESS;
}

OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    if (!session)
        return OEMCrypto_ERROR_INVALID_CONTEXT;

    pthread_mutex_lock(&g_oemcrypto_lock);

    if (!g_tee_initialized) {
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_OPEN_SESSION, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] OpenSession failed: 0x%08x\n", res);
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_OPEN_FAILURE;
    }

    *session = op.params[0].value.a;
    g_active_sessions++;

    pthread_mutex_unlock(&g_oemcrypto_lock);
    return OEMCrypto_SUCCESS;
}

OEMCryptoResult OEMCrypto_CloseSession(OEMCrypto_SESSION session)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    pthread_mutex_lock(&g_oemcrypto_lock);

    if (!g_tee_initialized) {
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_INVALID_SESSION;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = session;

    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_CLOSE_SESSION, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] CloseSession failed: 0x%08x\n", res);
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_CLOSE_FAILURE;
    }

    if (g_active_sessions > 0)
        g_active_sessions--;

    pthread_mutex_unlock(&g_oemcrypto_lock);
    return OEMCrypto_SUCCESS;
}

uint32_t OEMCrypto_APIVersion(void)
{
    return OEMCRYPTO_API_VERSION;
}

const char* OEMCrypto_SecurityLevel(void)
{
    return SECURITY_LEVEL_L1;
}

OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID, size_t* idLength)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    if (!deviceID || !idLength || *idLength == 0)
        return OEMCrypto_ERROR_SHORT_BUFFER;

    pthread_mutex_lock(&g_oemcrypto_lock);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = deviceID;
    op.params[0].tmpref.size = *idLength;

    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_GET_DEVICEID, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        pthread_mutex_unlock(&g_oemcrypto_lock);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    *idLength = op.params[0].tmpref.size;
    pthread_mutex_unlock(&g_oemcrypto_lock);
    return OEMCrypto_SUCCESS;
}

OEMCryptoResult OEMCrypto_GetRandom(uint8_t* randomData, size_t dataLength)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;

    if (!randomData || dataLength == 0)
        return OEMCrypto_ERROR_INVALID_CONTEXT;

    pthread_mutex_lock(&g_oemcrypto_lock);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = randomData;
    op.params[0].tmpref.size = dataLength;

    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_GET_RANDOM, &op, &err_origin);
    pthread_mutex_unlock(&g_oemcrypto_lock);

    return (res == TEEC_SUCCESS) ? OEMCrypto_SUCCESS : OEMCrypto_ERROR_UNKNOWN_FAILURE;
}

OEMCryptoResult OEMCrypto_DecryptCENC(
    OEMCrypto_SESSION session,
    const uint8_t* data_addr,
    size_t data_length,
    bool is_encrypted,
    const uint8_t* iv,
    size_t block_offset,
    const OEMCrypto_DestBufferDesc* out_buffer,
    const uint8_t* subsamples,
    size_t subsample_count)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    uint64_t dest_paddr = 0;

    (void)block_offset;
    (void)subsamples;
    (void)subsample_count;

    if (!data_addr || data_length == 0 || !out_buffer)
        return OEMCrypto_ERROR_INVALID_CONTEXT;

    /* Enforce Level 1 Security: Output must be a secure buffer handle */
    if (out_buffer->type != OEMCrypto_BufferType_Secure) {
        fprintf(stderr, "[OEMCrypto] Direct CPU buffers rejected: L1 hardware secure path required\n");
        return OEMCrypto_ERROR_SECURE_BUFFER_REQUIRED;
    }

    /* Extract destination physical address from secure buffer descriptor */
    dest_paddr = (uint64_t)(uintptr_t)out_buffer->buffer.secure.handle + out_buffer->buffer.secure.offset;

    pthread_mutex_lock(&g_oemcrypto_lock);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_VALUE_OUTPUT);

    /* Param 0: Encrypted input chunk in user RAM */
    op.params[0].tmpref.buffer = (void*)data_addr;
    op.params[0].tmpref.size = data_length;

    /* Param 1: Session context & encryption flags */
    op.params[1].value.a = session;
    op.params[1].value.b = is_encrypted ? 1 : 0;

    /* Param 2: Target secure physical address (low 32, high 32) */
    op.params[2].value.a = (uint32_t)(dest_paddr & 0xFFFFFFFF);
    op.params[2].value.b = (uint32_t)((dest_paddr >> 32) & 0xFFFFFFFF);

    /* Dispatch to OP-TEE TA: TrustZone performs AES-CTR/CBC decryption straight into DMC firewall */
    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_DECRYPTCENC, &op, &err_origin);

    pthread_mutex_unlock(&g_oemcrypto_lock);

    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[OEMCrypto] DecryptCENC failed in TrustZone: 0x%08x (origin 0x%x)\n",
                res, err_origin);
        return OEMCrypto_ERROR_DECRYPT_FAILED;
    }

    return OEMCrypto_SUCCESS;
}

OEMCryptoResult OEMCrypto_CopyBuffer(
    OEMCrypto_SESSION session,
    const uint8_t* data_addr,
    size_t data_length,
    const OEMCrypto_DestBufferDesc* out_buffer,
    uint8_t subsample_flags)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    uint64_t dest_paddr = 0;

    (void)subsample_flags;

    if (!data_addr || data_length == 0 || !out_buffer)
        return OEMCrypto_ERROR_INVALID_CONTEXT;

    if (out_buffer->type != OEMCrypto_BufferType_Secure)
        return OEMCrypto_ERROR_SECURE_BUFFER_REQUIRED;

    dest_paddr = (uint64_t)(uintptr_t)out_buffer->buffer.secure.handle + out_buffer->buffer.secure.offset;

    pthread_mutex_lock(&g_oemcrypto_lock);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE);

    op.params[0].tmpref.buffer = (void*)data_addr;
    op.params[0].tmpref.size = data_length;

    op.params[1].value.a = session;
    op.params[1].value.b = 0;

    op.params[2].value.a = (uint32_t)(dest_paddr & 0xFFFFFFFF);
    op.params[2].value.b = (uint32_t)((dest_paddr >> 32) & 0xFFFFFFFF);

    res = TEEC_InvokeCommand(&g_tee_session, TA_WVCENC_CMD_COPY_BUFFER, &op, &err_origin);
    pthread_mutex_unlock(&g_oemcrypto_lock);

    return (res == TEEC_SUCCESS) ? OEMCrypto_SUCCESS : OEMCrypto_ERROR_UNKNOWN_FAILURE;
}
