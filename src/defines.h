/**
 * @file
 * @brief Common defined macro statements
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
#ifndef _DEFINES_H
#define _DEFINES_H

/**
 * Name of the program
 */
#define PROGRAM_NAME "sealkey"

/**
 * Version of the program
 */
#define PROGRAM_VERSION "0.1.10"

/**
 * length of the static buffer we use for the options
 */
#define KERNEL_PARAMS_BUFFER_LEN 4098

/**
 * Path length for loader files on the EFI partition
 */
#define LOADER_ENTRY_PATH_LEN 255

/**
 * Default mount point of the EFI System Partition
 */
#define EFI_SYSTEM_PARTITION_MOUNT_POINT "/boot"

/**
 * Sysfs path to the system TPM device
 */
#define SYSFS_TPM_PATH "/sys/class/tpm/tpm0"

#ifdef DEBUG
#define MEASURE_CMDLINE_DEBUG_OUT 1
#define MEASURE_PE_DEBUG_OUT 1
#define PCR_DEBUG_OUT 1
#define SEALKEY_DEBUG_OUT 1
#define EFI_DEBUG_OUT 1
#else
#define MEASURE_CMDLINE_DEBUG_OUT 0
#define MEASURE_PE_DEBUG_OUT 0
#define PCR_DEBUG_OUT 0
#define SEALKEY_DEBUG_OUT 0
#define EFI_DEBUG_OUT 0
#endif

#endif // _DEFINES_H
