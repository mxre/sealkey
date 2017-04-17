/**
 * @file
 * @brief PE32+ image measurement for TPM 1.2
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
#ifndef _MEASURE_PE_H
#define _MEASURE_PE_H

#include <stdbool.h>

#include "tpm12_types.h"

/**
 * Calculate SHA1 for a PE32+ EFI executable file
 *
 * This method loads a PE32+ EFI application and generates
 * a SHA1 hash in the same way a the EFI LoadImage() function
 * would do for a TPM 1.2.
 *
 * This code was developed using OVMF Tiano Core and EDK II
 * as a reference for details look at 
 * `SecurityPkg/Library/DxeTpmMeasureBootLib/DxeTpmMeasureBootLib.c`
 * in the EDK II Tiano Core github repository.
 */
bool pe_image_measure1(const char* file, tpm_hash_t* hash);

#endif // _MEASURE_PE_H
