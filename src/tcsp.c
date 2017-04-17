/**
 * @copyright
 * Copyright 2017 Max Resch
 * <BR>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * <BR> 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "tcsp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include <tss/tspi.h>
#include <trousers/trousers.h>

#define BOOL bool
#include <tpm_tools/tpm_unseal.h>

#include "pcr.h"

static void tspi_error(const char* name, TSS_RESULT result) {
	fprintf(stderr, "%s failed: 0x%08x - layer=%s, code=%04x (%d), %s\n",
		 name, result, Trspi_Error_Layer(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_String(result));
}

// storage root key uuid
static TSS_UUID SRK_UUID = TSS_UUID_SRK;

// storage root well known secret
static uint8_t SRK_WELL_KNOWN_SECRET[TPM12_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

#define TPMSEAL_HDR_STRING "-----BEGIN TSS-----\n"
#define TPMSEAL_FTR_STRING "-----END TSS-----\n"
#define TPMSEAL_TSS_STRING "-----TSS KEY-----\n"
#define TPMSEAL_EVP_STRING "-----ENC KEY-----\n"
#define TPMSEAL_ENC_STRING "-----ENC DAT-----\n"

#define TPMSEAL_KEYTYPE_SYM "Symmetric Key: "
#define TPMSEAL_CIPHER_AES256CBC "AES-256-CBC\n"

#define TPMSEAL_SECRET "password"
#define TPMSEAL_IV "IBM SEALIBM SEAL"

ssize_t tcsp_seal_data(const uint8_t* data, const size_t len, const pcr_ctx_t* ctx, uint16_t selection, uint8_t** output) {
    assert(data);
    assert(ctx);
    assert(output);

    ssize_t ret = -1;
    const uint32_t aes_key_len = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    const uint32_t aes_block_len = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    TSS_FLAG rsa_key_flags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

    // outside of goto scope
    uint8_t line[aes_block_len * 16];
    uint8_t encrypted_data[sizeof(line) + aes_block_len];

    TSS_HCONTEXT tspi_context;
    TSS_RESULT result;
    if ((result = Tspi_Context_Create(&tspi_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Create", result);
        goto cleanup;
    }
    
    if ((result = Tspi_Context_Connect(tspi_context, NULL)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Connect", result);
        goto cleanup;
    }

    TSS_HPCRS pcr_context = 0;
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_PCRS, 0, &pcr_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
        goto cleanup;
    }

    for (int i = 0; i < PCR_LENGTH; i++) {
		if (selection & (1 << i)) {
            if ((result = Tspi_PcrComposite_SetPcrValue(pcr_context, i, TPM12_HASH_LEN, (uint8_t*) &ctx->pcrs[i])) != TSS_SUCCESS) {
                tspi_error("Tspi_PcrComposite_SetPcrValue", result);
                goto cleanup;
            }
        }
    }

    TSS_HKEY srk_handle;
    // get storage root key
    if ((result = Tspi_Context_LoadKeyByUUID(tspi_context, TSS_PS_TYPE_SYSTEM, SRK_UUID, &srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_LoadKeyByUUID", result);
		goto cleanup;
    }

    TSS_HPOLICY srk_policy;
    // get storage root key policy, for unlocking the root key
	if ((result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE, &srk_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_GetPolicyObject", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_SetSecret(srk_policy, TSS_SECRET_MODE_SHA1, sizeof(SRK_WELL_KNOWN_SECRET), (uint8_t*) SRK_WELL_KNOWN_SECRET)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_SetSecret", result);
		goto cleanup;
    }

    TPM_HANDLE tpm_handle = 0;
    if ((result = Tspi_Context_GetTpmObject(tspi_context, &tpm_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_GetTpmObject", result);
        goto cleanup;
    }

    uint8_t* random_key = NULL;
    // get random data as AES encryption key for stored secret
    if ((result = Tspi_TPM_GetRandom(tpm_handle, aes_key_len, &random_key)) != TSS_SUCCESS) {
        tspi_error("Tspi_TPM_GetRandom", result);
        goto cleanup;
    }

    TSS_HKEY rsa_key;
    // build an RSA object to encrypt the random key
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_RSAKEY, rsa_key_flags, &rsa_key)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
        goto cleanup;
    }

    TSS_HPOLICY rsa_policy;
    // create RSA policy
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &rsa_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_SetSecret(rsa_policy, TSS_SECRET_MODE_PLAIN, strlen(TPMSEAL_SECRET), (uint8_t*) TPMSEAL_SECRET)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_SetSecret", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_AssignToObject(rsa_policy, rsa_key)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
		goto cleanup;
    }

    // create RSA key under SRK, no PCRs
    if ((result = Tspi_Key_CreateKey(rsa_key, srk_handle, 0)) != TSS_SUCCESS) {
        tspi_error("Tspi_Key_CreateKey", result);
		goto cleanup;
    }

    // load the key
    if ((result = Tspi_Key_LoadKey(rsa_key, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Key_LoadKey", result);
		goto cleanup;
    }

    TSS_HENCDATA encrypted_data_handle;
    // create an encrypted data object
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
		goto cleanup;
    }

    TSS_HPOLICY data_policy;
    // create policy
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &data_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_SetSecret(data_policy, TSS_SECRET_MODE_PLAIN, strlen(TPMSEAL_SECRET), (uint8_t*) TPMSEAL_SECRET)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_SetSecret", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_AssignToObject(data_policy, encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
		goto cleanup;
    }

    // now set the data seal and encrypt the symetric key
    if ((result = Tspi_Data_Seal(encrypted_data_handle, rsa_key, aes_key_len, random_key, pcr_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Data_Seal", result);
		goto cleanup;
    }

    uint8_t* encrypted_blob;
    uint32_t encrypted_length;
    // get the encrypted symetric key
    if ((result = Tspi_GetAttribData(encrypted_data_handle, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encrypted_length, &encrypted_blob)) != TSS_SUCCESS) {
        tspi_error("Tspi_GetAttribData", result);
		goto cleanup;
    }

    uint8_t* seal_key;
    uint32_t seal_key_length;
    // get the sealing key
    if ((result = Tspi_GetAttribData(rsa_key, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &seal_key_length, &seal_key)) != TSS_SUCCESS) {
        tspi_error("Tspi_GetAttribData", result);
		goto cleanup;
    }

    BIO* input = BIO_new_mem_buf(data, len);
    BIO* out = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());

    // output sealed data header string
    BIO_puts(out, TPMSEAL_HDR_STRING);

    // output sealing key
    BIO_puts(out, TPMSEAL_TSS_STRING);
    out = BIO_push(b64, out);
    BIO_write(out, seal_key, seal_key_length);
    BIO_flush(out);
    out = BIO_pop(b64);

    // write sealed symmetric AES key
    BIO_puts(out, TPMSEAL_EVP_STRING);
	BIO_puts(out, TPMSEAL_KEYTYPE_SYM);
	BIO_puts(out, TPMSEAL_CIPHER_AES256CBC);
	out = BIO_push(b64, out);
	BIO_write(out, encrypted_blob, encrypted_length);
    BIO_flush(out);
    out = BIO_pop(b64);

    // encrypt data
    BIO_puts(out, TPMSEAL_ENC_STRING); 
    out = BIO_push(b64, out);
    int line_len;
    int encrypted_data_length;

    EVP_CIPHER_CTX *evp_cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(evp_cipher_ctx, EVP_aes_256_cbc(), random_key, (unsigned char*) TPMSEAL_IV);

    while ((line_len = BIO_read(input, line, sizeof(line))) > 0) {
        EVP_EncryptUpdate(evp_cipher_ctx, encrypted_data, &encrypted_data_length, line, line_len);
        BIO_write(out, encrypted_data, encrypted_data_length);
    }

    EVP_EncryptFinal(evp_cipher_ctx, encrypted_data, &encrypted_data_length);
    EVP_CIPHER_CTX_free(evp_cipher_ctx);

    BIO_write(out, encrypted_data, encrypted_data_length);
    BIO_flush(out);
    out = BIO_pop(b64);

    // end file
    BIO_puts(out, TPMSEAL_FTR_STRING);

    BIO_free(b64);
    BIO_free(input);

    // copy the output buffer, and free memory
    void* buffer = NULL;
    ret = BIO_get_mem_data(out, &buffer);
    *output = malloc(ret);
    memmove(*output, buffer, ret);
    BIO_free(out);

    // cleanup
    EVP_cleanup();
cleanup:

    if ((result = Tspi_Context_CloseObject(tspi_context, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, rsa_key)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, srk_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, rsa_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, data_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, pcr_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_FreeMemory(tspi_context, NULL)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_FreeMemory", result);
    }

    if ((result = Tspi_Context_Close(tspi_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Close", result);
    }

    return ret;
}

ssize_t tcsp_unseal_data(const char* filename, uint8_t** data) {
    int ret = -1;

    int result = 0;
    if ((result = tpmUnsealFile((char*) filename, data, &ret, true)) != 0) {
        const char* error = tpmUnsealStrerror(result);
        fprintf(stderr, "Error: tpm_unseal_file: %s\n", error);
        ret = -1;
    }

    return ret;
}
