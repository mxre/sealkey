/**
 * @file
 * @brief Seal data the same way tpm-tools would, but with custom defined PCRs
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
#ifndef _TCSP_H
#define _TCSP_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "pcr.h"

/**
 * Seal the data with PCR context and selected indices
 *
 * @param[in] data
 * @param[in] len
 * @param[in] ctx
 * @param[in] selection
 * @param[out] output
 * @returns lenght of output
 */
ssize_t tcsp_seal_data(const uint8_t* data, const size_t len, const pcr_ctx_t* ctx, uint16_t selection, uint8_t** output);

/**
 * Unseal sealed data
 *
 * @param[in] filename
 * @param[out] data
 * @returns length of data
 */
ssize_t tcsp_unseal_data(const char* filename, uint8_t** data);

#endif // _TCSP_H
