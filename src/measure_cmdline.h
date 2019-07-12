/**
 * @file
 * @brief Handle Kernel boot parameters from configuration file
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
#ifndef _MEASURE_CMDLINE_H
#define _MEASURE_CMDLINE_H

#include <stdlib.h>
#include <stdbool.h>

#include "tpm12_types.h"

/**
 * Create a hash for a initrd
 */
bool initrd_measure1(const char* initrd, tpm_hash_t* digest);

/**
 * Measure the kernel boot parameters the same way `systemd-boot` does.
 *
 * If systemd is compiled with TPM support the bootloader will hash
 * the kernel paramters passed to the EFI stup before invocation.
 * The default setting for systemd is to use PCR 8 for this measure.
 *
 * The resulting digest still has to be chained to be equivalent to
 * the one in PCR 8.
 *
 * @param cmdline kernel command line as in `/proc/cmdline`.
 * @param length string length of `cmdline` or `0` to use `strlen()`
 * @param[out] digest SHA1 digests
 */
bool kernel_params_measure1(const char* cmdline, size_t length, tpm_hash_t* digest);

/**
 * Measure the kernel commandline stored in the `.cmdline` section
 * 
 * When creating a systemd EFI bootstub for the kernel the commandline may be
 * stored in inside the UEFI executable.
 * 
 * @param file path to the UEFI executable
 * @param[out] digest SHA1 digest
 */
bool pe_params_measure1(const char* file, tpm_hash_t* digest);

#endif //_MEASURE_CMDLINE_H
