/**
 * @file
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

#include "measure_cmdline.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <uchar.h>
#include <assert.h>

#include <openssl/sha.h>
#include "tpm12_chain.h"
#include "systemd-boot.h"
#include "defines.h"

bool initrd_measure1(const char* initrd, tpm_hash_t* digest) {
    int fd;
    uint8_t* buffer = NULL;
    ssize_t len;

    if ((fd  = open(initrd, O_RDONLY)) < 0) {
        fprintf(stderr, "open: %m\n");
        return false;
    }
    
    if ((len = lseek(fd, 0, SEEK_END)) < 0) {
        fprintf(stderr, "seek: %m\n");
        close(fd);
        return false;
    }
    lseek(fd, 0, SEEK_SET);
    buffer = malloc(len);

    if (read(fd, buffer, (size_t) len) != len) {
        fprintf(stderr, "read: %m\n");
        free(buffer);
        close(fd);
        return false;
    }
    close(fd);

    SHA1(buffer, len, (uint8_t*) digest);

#if MEASURE_CMDLINE_DEBUG_OUT
    print_md(digest);
    printf("  %s: %zu\n", initrd, len);
#endif

    free(buffer);
    return true;
}

bool kernel_params_measure1(const char* cmdline, tpm_hash_t* digest) {
    int offset = 0;
    offset = strlen(cmdline);

    // include the NULL at the end of the string
    offset += 1;
    // Copy everything to a UTF16 string, the same way EFI does
    // this requires C11 libraries
    char16_t dest[KERNEL_PARAMS_BUFFER_LEN];
    mbstate_t state;
    memset(&state, 0, sizeof(state));

    for(int i = 0; i < offset; i++) {
        mbrtoc16(&dest[i], &cmdline[i], 1, &state);
    }

    SHA1((uint8_t*) dest, offset * 2, (uint8_t*) digest);

#if MEASURE_CMDLINE_DEBUG_OUT
    print_md(digest);
    printf("  bootops\n");
#endif

    return true;
}
