/**
 * @file
 * @brief PCR structures and functions for system interaction
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
#ifndef _PCR_H
#define _PCR_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "util.h"
#include "tpm12_types.h"

/**
 * For now only use the basic 0-15 PCRs
 * 
 * PCRs < 7 store information hashed by the firmware and
 * PCRs 8 to 15 are managed by the operating system and the bootloader
 *
 * Higher PCRs are for debug and application use and only present in TPM 1.2
 */
#define PCR_LENGTH 16

/**
 * A list of PCRs provided by the OS
 */
typedef struct {
	tpm_hash_t pcrs[PCR_LENGTH];
} pcr_ctx_t;

/**
 * Part of TSS definition
 */
typedef struct {
    // stored in big endian for some reason
    uint16_t sizeOfSelect;
    // 2 we do not allow PCR > 15
    uint8_t pcrSelect[2];
} pcr_selection_t;

/**
 * Part of TSS definition
 */
typedef struct {
    pcr_selection_t pcrSelection;
    tpm_hash_t digestAtRelease;
    // let this be zeros
    tpm_hash_t digestAtCreation;
} pcr_info_t;

/**
 * Context to construct a composite PCR hash
 */
typedef struct {
    uint8_t pcrSelect[2];
    tpm_hash_t pcrList[PCR_LENGTH];
} pcr_composite_ctx_t;

/**
 * Initialize the PCR composite
 *
 * @relates pcr_composite_ctx_t
 */
static inline void pcr_composite_init(pcr_composite_ctx_t* ctx) {
    memset(ctx, 0, sizeof(pcr_composite_ctx_t));
}

/**
 * Get a hex string representing the TSS PCR_INFO type
 *
 * @note Buffer must be long enough to hold the string, which
 *       is always 89 characters long.
 *
 * @relates pcr_composite_ctx_t
 */
void pcr_composite_get_info_hex(pcr_composite_ctx_t* ctx, char* buffer);

/**
 * Add a PCR hash to the composite
 *
 * @relates pcr_composite_ctx_t
 */
void pcr_composite_set(pcr_composite_ctx_t* ctx, uint8_t idx, tpm_hash_t* value);

/**
 * Read the PCRs from the operation system
 *
 * This will parse `/sys/class/tpm/tpm0/pcrs` file
 * which is readable by everyone on Linux, if the
 * TPM is present configured and loaded.
 *
 * @relates pcr_ctx_t
 */
bool pcr_ctx_from_system(pcr_ctx_t* ctx);

#endif // _PCR_H
