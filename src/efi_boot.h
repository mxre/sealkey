/**
 * @file
 * @brief Getting EFI boot entries
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
#ifndef _EFI_BOOT_H
#define _EFI_BOOT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Get the default boot entry
 *
 * @param[out] path to the EFI executable (or NULL, only return value os provided)
 * @param[in] len length of the buffer, pointed to by path.
 * @returns length of the path
 */
int efi_boot_get_default(char* path, size_t len);

/**
 * Get the current boot entry
 *
 * @param[out] path to the EFI executable (or NULL, only return value os provided)
 * @param[in] len length of the buffer, pointed to by path.
 * @returns length of the path
 */
int efi_boot_get_current(char* path, size_t len);

/**
 * Get the a boot entry with the privided number
 *
 * @param[in] entry nu,ber of the EFI boot entry
 * @param[out] path to the EFI executable (or NULL, only return value os provided)
 * @param[in] len length of the buffer, pointed to by path.
 * @returns length of the path
 */
int efi_boot_get_numbered(const uint16_t entry, char* path, size_t len);

/**
 * Determine the ESP from EFI variables set by systemd-boot
 * 
 * @param[out] esp 
 * @return true on success
 */
bool efi_boot_get_esp(char* esp);

#endif // _EFI_BOOT_H
