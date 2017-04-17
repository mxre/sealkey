/**
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

#include "measure_cmdline.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <uchar.h>
#include <assert.h>

#include <openssl/sha.h>
#include "tpm12_chain.h"

/**
 * length of the static buffer we use for the options
 */
#define KERNEL_PARAMS_BUFFER_LEN 1024

int parse_boot_option(char* bf, char** pos, const char* opt_name, char* value) {
    assert(bf);
    assert(opt_name);
    assert(value);
    
    char* buffer;
	if (pos == NULL)
		buffer = bf;
	else
		buffer = *pos == NULL ? bf : *pos;

    char name[128];
    int name_len = snprintf(name, 127, "\n%s ", opt_name);

    char* options = strstr(buffer, name);
    if (options == NULL)
        return -1;
    
    options += name_len;
    char* options_end = strchr(options, '\n');
    size_t len;
    for (; isspace(*options); options++);
    if (options_end != NULL)
        len = options_end - options;
    else
        len = strlen(options);
    assert(len > 0);
    for (; isspace(options[len - 1]); len--);
    if (pos != NULL)
	    *pos = options_end;

    strncpy(value, options, len);
    value[len] = 0;

    return len;
}

static inline bool kernel_params_open(const char* file, char** buffer) {
    assert(file);
    assert(buffer);

    int fd = -1;
    bool ret = false;
    
    fd = open(file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error: open: %m\n");
        goto cleanup;
    }

    off_t buf_len = lseek(fd, 0, SEEK_END);
    if (buf_len < 0) {
        fprintf(stderr, "Error: seek: %m\n");
        goto cleanup;
    }
    lseek(fd, 0, SEEK_SET);

    *buffer = malloc(buf_len + 1);
    if (*buffer == NULL) {
        fprintf(stderr, "Error: malloc: %m\n");
        goto cleanup;
    }

    if (read(fd, *buffer, buf_len) < 0) {
        fprintf(stderr, "Error: read: %m\n");
        goto cleanup;
    }

    (*buffer)[buf_len] = '\0';
    ret = true;

cleanup:
    if (fd >= 0)
        close(fd);
    if (!ret && *buffer == NULL) {
        free(*buffer);
        *buffer = NULL;
    }

    return ret;
}

bool kernel_params_measure1(const char* file, tpm_hash_t* digest) {
    bool ret = false;
    char* buffer = NULL;

    if (!kernel_params_open(file, &buffer)) {
        goto cleanup;
    }

    char result[KERNEL_PARAMS_BUFFER_LEN];
    char option[KERNEL_PARAMS_BUFFER_LEN];
    char* tok = NULL;
    int offset = 0;
    int len = 0;

    // initrd may be passed multiple times
    while ((len = parse_boot_option(buffer, &tok, "initrd", option)) > 0) {
        offset += sprintf(result + offset, "initrd=%s ", option);
    }

    // initrd are passed as EFI file paths, relative to ESP root
    // so all / are infact \ (see /proc/cmdline)
    for (char* iter = result; iter - result < offset && *iter != 0; iter++) {
        if (*iter == '/')
            *iter = '\\';
    }

    // reset
    tok = NULL;
    // parse actual kernel parameters
    if ((len = parse_boot_option(buffer, &tok, "options", result + offset)) > 0) {
        offset += len;
        result[offset] = 0;
    }

    // include the NULL at the end of the string
    offset += 1;
    // Copy everything to a UTF16 string, the same way EFI does
    // this requires C11 libraries
    char16_t dest[KERNEL_PARAMS_BUFFER_LEN];
    mbstate_t state;
    memset(&state, 0, sizeof(state));

    for(int i = 0; i < offset; i++) {
        mbrtoc16(&dest[i], &result[i], 1, &state);
    }

    SHA1((uint8_t*) dest, offset * 2, (uint8_t*) digest);
    ret = true;
cleanup:
    if (buffer != NULL)
        free(buffer);

    return ret;
}
