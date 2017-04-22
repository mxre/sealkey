/**
 * @file
 * @brief Utility functions
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
#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdint.h>

#include "tpm12_types.h"

/**
 * Print a data as a string of hexadecimals, followed by a newline
 */
static inline void print_hex(uint8_t* data, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%02hhx", *(data + i));
	}
	printf("\n");
}

/**
 * Print a SHA1 message Digest
 */
static inline void print_md(tpm_hash_t* md) {
    uint8_t* d = (uint8_t*) md;
    printf(TPM12_HASH_FORMAT_STRING,
            d[0],  d[1],  d[2],  d[3],  d[4],  d[5],  d[6],  d[7],  d[8],  d[9],
           d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17], d[18], d[19]);
}

/**
 * Arbitrary hex string creation
 */
static inline void hex_string(char* out, uint8_t* data, uint32_t len) {
	uint32_t i = 0;
	for (; i < len; i++) {
		sprintf(out + 2*i, "%02hhx", *(data + i));
	}
}

#endif // _UTIL_H
