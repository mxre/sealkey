/**
 * @file
 *
 * @copyright
 * Copyright 2018 Max Resch
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

#include "hash.h"

#include <stdlib.h>

#if USE_OPENSSL
hash_algo_t HASH_SHA1 = NULL;
#elif USE_GCRYPT
hash_algo_t HASH_SHA1 = GCRY_MD_SHA1;
#endif

void hash_lib_init() {
#if USE_OPENSSL
    HASH_SHA1 = EVP_sha1();
#elif USE_GCRYPT
    if (!gcry_check_version (GCRYPT_VERSION)) {
        fputs ("libgcrypt version mismatch\n", stderr);
        exit (2);
    }
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
}

hash_error_t hash(hash_algo_t algo, const void* buffer, size_t len, void* digest) {
    if (buffer == NULL) {
        return HASH_ERROR_INVALID_POINTER;
    }
#if USE_OPENSSL
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, algo, NULL);
    EVP_DigestUpdate(ctx, buffer, len);
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_destroy(ctx);
#elif USE_GCRYPT
    gcry_md_hash_buffer(algo, digest, buffer, len);
#endif
    return 0;
}

size_t hash_length(hash_algo_t algo) {
#if USE_OPENSSL
    return (size_t) EVP_MD_size(algo);
#elif USE_GCRYPT
    return (size_t) gcry_md_get_algo_dlen(algo);
#endif
}

hash_ctx_t hash_create_ctx(hash_algo_t algo) {
#if USE_OPENSSL
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, algo, NULL);
    return ctx;
#elif USE_GCRYPT
    gcry_md_hd_t ctx;
    gcry_md_open(&ctx, algo, 0);
    return ctx;
#endif
}

void hash_update(hash_ctx_t ctx, void* buffer, size_t len) {
#if USE_OPENSSL
    EVP_DigestUpdate(ctx, buffer, len);
#elif USE_GCRYPT
    gcry_md_write(ctx, buffer, len);
#endif
}

hash_error_t hash_finalize(hash_ctx_t ctx, void* digest, size_t len) {
#if USE_OPENSSL
    EVP_DigestFinal_ex(ctx, digest, (unsigned int*) &len);
#elif USE_GCRYPT
    gcry_md_extract(ctx, 0, digest, len);
#endif
    return 0;
}

void hash_ctx_reset(hash_ctx_t ctx) {
#if USE_OPENSSL
    EVP_MD const* algo = EVP_MD_CTX_md(ctx);
    EVP_MD_CTX_reset(ctx);
    EVP_DigestInit_ex(ctx, algo, NULL);
#elif USE_GCRYPT
    gcry_md_reset(ctx);
#endif
}

void hash_free_ctx(hash_ctx_t ctx) {
#if USE_OPENSSL
    EVP_MD_CTX_free(ctx);
#elif USE_GCRYPT
    gcry_md_close(ctx);
#endif
}
