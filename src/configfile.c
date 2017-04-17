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
#include "configfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <json-c/json.h>

bool configfile_read(const char* path, json_object_t* configuration) {
    assert(configuration);
    assert(path);

    int fd = -1;
    struct json_tokener* tok = NULL;
    struct json_object* cfg_file = NULL;
    char* buffer = NULL;
    bool ret = false;
    
    fd = open(path, O_RDONLY);
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

    buffer = malloc(buf_len);
    if (buffer == NULL) {
        fprintf(stderr, "Error: malloc: %m\n");
        goto cleanup;
    }

    if (read(fd, buffer, buf_len) < 0) {
        fprintf(stderr, "Error: read: %m\n");
        goto cleanup;
    }

    tok = json_tokener_new();
    cfg_file = json_tokener_parse_ex(tok, buffer, buf_len);
    if (cfg_file == NULL) {
        const char* json_error = json_tokener_error_desc(json_tokener_get_error(tok));
        fprintf(stderr, "Error: json_parse: %s\n", json_error);
        goto cleanup;
    }

    *configuration = cfg_file;
    ret = true;
cleanup:
    if (tok)
        json_tokener_free(tok);
    if (fd >= 0)
        close(fd);
    if (buffer)
        free(buffer);

    return ret;
}
