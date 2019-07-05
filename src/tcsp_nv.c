/**
 * @file
 *
 * @copyright
 * Copyright 2019 Max Resch
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

#include "tcsp_nv.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <tss/tspi.h>
// needed for error handling
#include <trousers/trousers.h>

static void tspi_error(const char* name, TSS_RESULT result) {
	fprintf(stderr, "%s failed: 0x%08x - layer=%s, code=%04x (%u), %s\n",
		 name, result, Trspi_Error_Layer(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_Code(result),
		 Trspi_Error_String(result));
}

bool tcsp_nv_write(const uint32_t nv_address, uint8_t* blob, size_t length) {
    assert(blob);

    bool ret = false;

    TSS_HCONTEXT ctx;
    TSS_RESULT result;
    if ((result = Tspi_Context_Create(&ctx)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Create", result);
        goto cleanup;
    }
    
    if ((result = Tspi_Context_Connect(ctx, NULL)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Connect", result);
        goto cleanup;
    }

    TSS_HNVSTORE nv;
    TSS_FLAG nvattrs = 0;
    if ((result = Tspi_Context_CreateObject(ctx, TSS_OBJECT_TYPE_NV, nvattrs, &nv)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CreateObject", result);
        goto cleanup_nv;
    }

    if ((result = Tspi_SetAttribUint32(nv, TSS_TSPATTRIB_NV_INDEX, 0, nv_address)) != TSS_SUCCESS) {
        tspi_error("Tspi_SetAttribUint32", result);
        goto cleanup_nv;
    }

    if ((result = Tspi_SetAttribUint32(nv, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERREAD | TPM_NV_PER_OWNERWRITE)) != TSS_SUCCESS) {
        tspi_error("Tspi_SetAttribUint32", result);
        goto cleanup_nv;
    }

    if ((result = Tspi_SetAttribUint32(nv, TSS_TSPATTRIB_NV_DATASIZE, 0, (uint32_t) length)) != TSS_SUCCESS) {
        tspi_error("Tspi_SetAttribUint32", result);
        goto cleanup_nv;
    }

    result = Tspi_NV_DefineSpace(nv, 0, 0);
    if (result != TSS_SUCCESS && result != (0x3000 | TSS_E_NV_AREA_EXIST)) {
        tspi_error("Tspi_NV_DefineSpace", result);
        goto cleanup_nv;
    }

    if ((result = Tspi_NV_WriteValue(nv, 0, (uint32_t) length, blob)) != TSS_SUCCESS) {
        tspi_error("Tspi_NV_WriteValue", result);
        goto cleanup_nv;
    }

    ret = true;

cleanup_nv:
    if ((result = Tspi_Context_CloseObject(ctx, nv)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_CloseObject", result);
    }

cleanup:
    if ((result = Tspi_Context_FreeMemory(ctx, NULL)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_FreeMemory", result);
    }

    if ((result = Tspi_Context_Close(ctx)) != TSS_SUCCESS) {
        tspi_error("Tspi_Context_Close", result);
    }

    return ret;
}
