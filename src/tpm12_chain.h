/**
 * @file
 * @brief Create SHA1 hash chain for TPM PCR creation
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

#pragma once
#ifndef _TPM12_CHAIN_H
#define _TPM12_CHAIN_H

#include <stdint.h>
#include <string.h>

#include "util.h"
#include "hash.h"
#include "tpm12_types.h"

/**
 * TPM chained SHA1 context
 */
typedef struct {
	tpm_hash_t digest[2];
	hash_ctx_t ctx;
} TPM12_Chain_Context;

/**
 * Initialize chained hash context
 *
 * @relates TPM12_Chain_Context
 */
static inline void TPM12_Chain_Init(TPM12_Chain_Context* ctx) {
	memset(ctx->digest, 0, 2 * TPM12_HASH_LEN);
    ctx->ctx = hash_create_ctx(HASH_SHA1);
}

/**
 * Update chained hash context with specified hash value
 *
 * @relates TPM12_Chain_Context
 */
static inline void TPM12_Chain_Update(TPM12_Chain_Context* ctx, const tpm_hash_t* hash) {
	memcpy(&ctx->digest[1], hash, TPM12_HASH_LEN);
	hash_update(ctx->ctx, (uint8_t*) ctx->digest, 2 * TPM12_HASH_LEN);
	hash_finalize(ctx->ctx, (uint8_t*) &ctx->digest[0], TPM12_HASH_LEN);
    hash_ctx_reset(ctx->ctx);
}

/**
 * Return the final hash
 *
 * @relates TPM12_Chain_Context
 */
static inline void TPM12_Chain_Finalize(TPM12_Chain_Context* ctx, tpm_hash_t* hash) {
	memcpy(hash, &ctx->digest[0], TPM12_HASH_LEN);
}

#endif // TPM12_CHAIN_H
