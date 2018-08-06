/**
 * @file
 * @brief Shim for different crypto libraries
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
#ifndef __HASH_H__
#define __HASH_H__

#if USE_OPENSSL
#include <openssl/evp.h>
#elif USE_GCRYPT
#include <gcrypt.h>
#else
#error "No Crypto Backend use -DUSE_OPENSSL=1 or -DUSE_GCRYPT=1"
#endif

/// Hash function context
typedef
#ifdef USE_OPENSSL
    EVP_MD_CTX*
#elif USE_GCRYPT
    gcry_md_hd_t
#else
    void*
#endif
hash_ctx_t;

/// Hash algorithm handle 
typedef
#ifdef USE_OPENSSL
    EVP_MD const*
#elif USE_GCRYPT
    int
#else
    void*
#endif
hash_algo_t;

/// SHA1 algorithm
extern hash_algo_t HASH_SHA1;

typedef enum {
    HASH_ERROR_SUCCESS,
    HASH_ERROR_INVALID_POINTER,
    HASH_ERROR_NOT_ENOUGH_SPACE
} hash_error_t;

/**
 * Initialize digest library
 * 
 * This function should be called once at the start of the
 * program.
 */
void hash_lib_init();

/**
 * Convenience function to calculate a hash value
 * 
 * @param algo
 *  Algorithm handle
 * @param buffer
 *  Buffer containing the message, shall not be `NULL`
 * @param len
 *  Length of the buffer
 * @param digest
 *  Resulting message digest, this buffer should have the appropriate size returned by #hash_length
 * @returns `0` or error code
 */
hash_error_t hash(hash_algo_t algo, const void* buffer, size_t len, void* digest);

/**
 * Get size of the resulting message digest
 */
size_t hash_length(hash_algo_t algo);

/**
 * Create a new hash context for specified algorithm
 *
 * @returns New context or `NULL` on error
 */
hash_ctx_t hash_create_ctx(hash_algo_t algo);

/**
 * Free the memory of a context
 */
void hash_free_ctx(hash_ctx_t ctx);

/**
 * Reset hash context reuse
 * 
 * Use this function, to reuse an existing hash context, instead
 * of freeing and creating a new one.
 */
void hash_ctx_reset(hash_ctx_t ctx);

/**
 * Update hash context with buffer contents
 *
 * @param ctx
 *  Context to update
 * @param buffer
 *  Buffer containing message, shall not be `NULL`
 * @param len
 *  Lenth of the buffer
 */
void hash_update(hash_ctx_t ctx, void* buffer, size_t len);

/**
 * Finalize hash function and calculate message digest
 * 
 * @param ctx 
 *  hash context
 * @param digest
 *  resulting digest 
 * @param len
 *  lenght of the digest buffer, must be at least #hash_length
 * @returns `0` or error code
 */
hash_error_t hash_finalize(hash_ctx_t ctx, void* digest, size_t len);

#endif // __SHA1_H__
