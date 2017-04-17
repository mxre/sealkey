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

#include "pcr.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <openssl/sha.h>

#include "util.h"

// path to the sysfs TPM
#define SYSFS_TPM_PATH "/sys/class/tpm/tpm0"

bool pcr_ctx_from_system(pcr_ctx_t* ctx) {
	bool ret = false;
    char* buffer = NULL;
    
	int fd = open(SYSFS_TPM_PATH "/pcrs", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: open: %m\n");
		goto cleanup;
	}
	
    // get the file size
    // since sysfs, it probaly will always return 4096
	off_t len = lseek(fd, 0, SEEK_END);
    if (len < 0) {
        fprintf(stderr, "Error: seek: %m\n");
        goto cleanup;
    }
	lseek(fd, 0, SEEK_SET);
	
	buffer = malloc(len);
	if (buffer == NULL) {
		fprintf(stderr, "Error: malloc: %m\n");
		goto cleanup;
	}
	
	if ((len = read(fd, buffer, len)) < 0) {
		fprintf(stderr, "Error: read: %m\n");
		goto cleanup;
	}

    // end string
    buffer[len] = 0;
	
	close(fd);
	fd = -1;
	
    char pcrname[10];
    // parse the PCR from strings
    for (int i = 0; i < PCR_LENGTH; i++) {
        snprintf(pcrname, 10, "PCR-%02d: ", i);
        char* pcr = strstr(buffer, pcrname);
        if (pcr == NULL) {
            fprintf(stderr, "Error: Could not find PCR %02d\n", i);
            goto cleanup;
        }

        uint8_t* hash = ctx->pcrs[i].digest;
        if (sscanf(pcr + 8, "%hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX",
            &hash[0], &hash[1], &hash[2], &hash[3], &hash[4], &hash[5], &hash[6], &hash[7], &hash[8], &hash[9],
            &hash[10], &hash[11], &hash[12], &hash[13], &hash[14], &hash[15], &hash[16], &hash[17], &hash[18], &hash[19]) != 20)
        {
            fprintf(stderr, "Error: Could not scanf\n");
            goto cleanup;
        }

#ifdef DEBUG
        printf("PCR[%02d] ", i);
        print_hex(ctx->pcrs[i].digest, TPM12_HASH_LEN);
#endif
    }
	
	ret = true;
cleanup:
	if (buffer)
		free(buffer);
	if (fd > 0)
		close(fd);
	
	return ret;
}

void pcr_composite_get_info_hex(pcr_composite_ctx_t* ctx, char* buffer) {
    assert(buffer != NULL);
    assert(ctx != NULL);
    
    // PCR_INFO structure
    pcr_info_t info;
    memset(&info, 0, sizeof(pcr_info_t));
    uint16_t sz = 2;
    info.pcrSelection.sizeOfSelect = (sz >> 8) | (sz << 8);
    memcpy(info.pcrSelection.pcrSelect, ctx->pcrSelect, 2);

    uint8_t hash_buffer[1024];
    memset(hash_buffer, 0, 1024);

    // 1. write pcr selection
    memcpy(hash_buffer, (uint8_t*) &info.pcrSelection, 4);

    // 2. assemble the hashes
    // leave space (sizeof(uint32_t)) for the length specifier, added later
    size_t offset = 8;
    uint8_t count = 0;
    for (uint8_t i = 0; i < PCR_LENGTH; i++) {
        if (ctx->pcrSelect[i / 8] & (1 << (i % 8))) {
            memcpy(hash_buffer + offset, &ctx->pcrList[i], TPM12_HASH_LEN);
            offset += TPM12_HASH_LEN;
            count++;
        }
    }

    // 3. write the length as a uint32_t big endian 
    uint8_t* out = hash_buffer + 4;
    uint32_t i = count * TPM12_HASH_LEN;
    out[0] = (uint8_t) ((i >> 24) & 0xFF);
	out[1] = (uint8_t) ((i >> 16) & 0xFF);
	out[2] = (uint8_t) ((i >> 8) & 0xFF);
	out[3] = (uint8_t) i & 0xFF;

    // print_hex(hash_buffer, 1024);
    
    // 4. hash the structure and write the digest in the field of the info struct
    SHA1(hash_buffer, offset, (uint8_t*) &info.digestAtRelease);
    hex_string(buffer, (uint8_t*) &info, sizeof(pcr_info_t));
}

void pcr_composite_set(pcr_composite_ctx_t* info, uint8_t idx, tpm_hash_t* value) {
    assert(info != NULL);
    assert(value != NULL);
    assert(idx < PCR_LENGTH);

    info->pcrSelect[idx / 8] |= (1 << (idx % 8));
    memcpy(&info->pcrList[idx], value, TPM12_HASH_LEN);
}
