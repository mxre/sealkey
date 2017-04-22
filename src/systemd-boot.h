/**
 * @file
 * @brief Parsing and utilities for systemd-boot conf files
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
#ifndef _SYSTEMD_BOOT_H
#define _SYSTEMD_BOOT_H

#include <stdbool.h>

/**
 * Open the file and put contents in allocated buffer
 */
bool systemd_boot_open(const char* file, char** buffer);

/**
 * Parse an option and copy it's contents to another buffer
 *
 * @param[in] buffer
 *       Buffer holding the boot options configuration file
 * @param[in,out] pos
 *       If this is set to a pointer, parsing will begin from this position,
 *       and a pointer past the end of the option will be written to that pointer.
 *       On first call set it to a pointer variable with `NULL` to start parsing
 *       from the beginning.
 *       Can be set to `NULL`, were no position is returned and the whole file is parsed.
 * @param[in] opt_name
 *       Name of the option
 * @param[out] value
 *       Value of the option, buffer must be large enough
 * @returns length of the string written to `value`
 */
int systemd_boot_parse_option(char* buffer, char** pos, const char* opt_name, char* value);

#endif // _SYSTEMD_BOOT_H
