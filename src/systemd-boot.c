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

#include "systemd-boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

int systemd_boot_parse_option(char* buffer, char** pos, const char* opt_name, char* value) {
    assert(buffer);
    assert(opt_name);
    assert(value);
    
    char* bf;
	if (pos == NULL)
		bf = buffer;
	else
		bf = *pos == NULL ? buffer : *pos;

    char name[128];
    int name_len = snprintf(name, 127, "\n%s ", opt_name);

    char* options = strstr(bf, name);
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

bool systemd_boot_open(const char* file, char** buffer) {
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
