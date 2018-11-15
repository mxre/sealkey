/**
 * @file
 *
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

#include <tss/tspi.h>
// needed for error handling
#include <trousers/trousers.h>

#include "pcr.h"

static void tspi_error(const char* name, TSS_RESULT result) {
	fprintf(stderr, "%s failed: 0x%08x - layer=%s, code=%04x (%u), %s\n",
		 name, result, Trspi_Error_Layer(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_String(result));
}

// storage root key uuid
static TSS_UUID SRK_UUID = TSS_UUID_SRK;

// storage root well known secret
static uint8_t SRK_WELL_KNOWN_SECRET[TPM12_HASH_LEN] = TSS_WELL_KNOWN_SECRET;

ssize_t tcsp_seal_data(const uint8_t* data, const size_t len, const pcr_ctx_t* ctx, uint32_t selection, uint8_t** output) {
    assert(data);
    assert(ctx);
    assert(output);

    ssize_t ret = -1;

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

    TPM_HANDLE tpm_handle = 0;
    if ((result = Tspi_Context_GetTpmObject(tspi_context, &tpm_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_GetTpmObject", result);
        goto cleanup;
    }

    TSS_HPCRS pcr_context = 0;
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_PCRS, 0, &pcr_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
        goto cleanup;
    }

    for (uint32_t mask = 1, i = 0; i < PCR_LENGTH; i++, mask <<= 1) {
		if (selection & mask) {
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

    if ((result = Tspi_Policy_AssignToObject(srk_policy, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
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

    if ((result = Tspi_Policy_SetSecret(data_policy, TSS_SECRET_MODE_SHA1, sizeof(SRK_WELL_KNOWN_SECRET), (uint8_t*) SRK_WELL_KNOWN_SECRET)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_SetSecret", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_AssignToObject(data_policy, encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
		goto cleanup;
    }

    // now seal the data
    if ((result = Tspi_Data_Seal(encrypted_data_handle, srk_handle, (uint32_t) len, (uint8_t*) data, pcr_context)) != TSS_SUCCESS) {
        tspi_error("Tspi_Data_Seal", result);
		goto cleanup;
    }

    uint8_t* encrypted_blob;
    uint32_t encrypted_length;
    // get the encrypted data key
    if ((result = Tspi_GetAttribData(encrypted_data_handle, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, &encrypted_length, &encrypted_blob)) != TSS_SUCCESS) {
        tspi_error("Tspi_GetAttribData", result);
		goto cleanup;
    }

    *output = malloc((size_t) encrypted_length);
    memcpy(*output, encrypted_blob, encrypted_length);
    ret = encrypted_length;

    Tspi_Context_FreeMemory(tspi_context, encrypted_blob);

cleanup:
    if ((result = Tspi_Context_CloseObject(tspi_context, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, srk_policy)) != TSS_SUCCESS) {
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

ssize_t tcsp_unseal_data(const uint8_t* input, const size_t length, uint8_t** data) {
    assert(input);

    ssize_t ret = -1;

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

    if ((result = Tspi_Policy_AssignToObject(srk_policy, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
        goto cleanup;
    }

    TSS_HENCDATA encrypted_data_handle;
    // create an encrypted data object
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_SEAL, &encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
		goto cleanup;
    }

    // set the encrypted data key
    if ((result = Tspi_SetAttribData(encrypted_data_handle, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, length, (uint8_t*) input)) != TSS_SUCCESS) {
        tspi_error("Tspi_SetAttribData", result);
		goto cleanup;
    }

    TSS_HPOLICY policy;
    // create policy
    if ((result = Tspi_Context_CreateObject(tspi_context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_SetSecret(policy, TSS_SECRET_MODE_SHA1, sizeof(SRK_WELL_KNOWN_SECRET), (uint8_t*) SRK_WELL_KNOWN_SECRET)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_SetSecret", result);
		goto cleanup;
    }

    if ((result = Tspi_Policy_AssignToObject(policy, encrypted_data_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Policy_AssignToObject", result);
		goto cleanup;
    }

    uint32_t out_len = 0;
    uint8_t* out_data;
    // now unseal the data
    if ((result = Tspi_Data_Unseal(encrypted_data_handle, srk_handle, &out_len, &out_data)) != TSS_SUCCESS) {
        tspi_error("Tspi_Data_Unseal", result);
		goto cleanup;
    }

    *data = malloc(out_len);
    memcpy(*data, out_data, out_len);
    Tspi_Context_FreeMemory(tspi_context, out_data);
    ret = out_len;

cleanup:
    if ((result = Tspi_Context_CloseObject(tspi_context, srk_handle)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, srk_policy)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

    if ((result = Tspi_Context_CloseObject(tspi_context, policy)) != TSS_SUCCESS) {
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
