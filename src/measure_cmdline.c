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

#include <sys/stat.h>
#include <sys/mman.h>

#include "pe.h"
#include "tpm12_chain.h"
#include "hash.h"
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

    hash(HASH_SHA1, buffer, len, (uint8_t*) digest);

#if MEASURE_CMDLINE_DEBUG_OUT
    print_md(digest);
    printf(" %s\n", initrd);
#endif

    free(buffer);
    return true;
}

bool kernel_params_measure1(const char* cmdline, size_t length, tpm_hash_t* digest) {
    int offset = 0;
    offset = length > 0 ? length : strlen(cmdline);

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

    hash(HASH_SHA1, (uint8_t*) dest, offset * 2, (uint8_t*) digest);

#if MEASURE_CMDLINE_DEBUG_OUT
    print_md(digest);
    printf(" %s\n", cmdline);
#endif

    return true;
}

bool pe_params_measure1(const char* file, tpm_hash_t* digest) {
    assert(file);

    bool ret = false;

    int fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: open: %m\n");
		return ret;
	}

    struct statx* st = (struct statx*) malloc(sizeof(struct statx));
	statx(fd, "", AT_EMPTY_PATH, STATX_SIZE, st);
    size_t filesize = st->stx_size;
    free(st);

    uint8_t* pe_image = mmap(NULL, filesize, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (pe_image == MAP_FAILED) {
		fprintf(stderr, "Error: mmap: %m\n");
		goto cleanup;
	}
	
	if ((*(uint16_t*) pe_image) != EFI_IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "Error: MZ magic\n");
		goto cleanup;
	}	
	
	EFI_IMAGE_DOS_HEADER* dos_image_header = (EFI_IMAGE_DOS_HEADER*) pe_image;
	uint32_t pe_offset = dos_image_header->e_lfanew;
	
	EFI_IMAGE_NT_HEADERS64* pe_image_header = (EFI_IMAGE_NT_HEADERS64*) (pe_image + pe_offset);
	
	if (pe_image_header->Signature != EFI_IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "Error: PE magic\n");
		goto cleanup;
	}
	
	
	if ((pe_image_header->FileHeader.Characteristics & EFI_IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
		fprintf(stderr, "Error: Not an executable: 0x%04x\n", pe_image_header->FileHeader.Characteristics);
		goto cleanup;
	}
	
	if (pe_image_header->FileHeader.Machine != IMAGE_FILE_MACHINE_X64) {
		fprintf(stderr, "Error: Not a x64 binary: 0x%04x\n", pe_image_header->FileHeader.Machine);
		goto cleanup;
	}
	
	if (pe_image_header->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		fprintf(stderr, "Error: Not a PE32+ binary: %04hx\n", pe_image_header->OptionalHeader.Magic);
		goto cleanup;
	}
		
	if (pe_image_header->OptionalHeader.Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
		fprintf(stderr, "Error: Not a EFI application: 0x%02hx\n", pe_image_header->OptionalHeader.Subsystem);
		goto cleanup;
	}

    EFI_IMAGE_SECTION_HEADER* section_header = malloc(pe_image_header->FileHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER));
	if (section_header == NULL) {
		fprintf(stderr, "Error malloc: %m\n");
		goto cleanup;
	}

    memset(section_header, 0, pe_image_header->FileHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER));
    
    EFI_IMAGE_SECTION_HEADER* section = (EFI_IMAGE_SECTION_HEADER*) (
		pe_image + 
		pe_offset + sizeof(EFI_IMAGE_FILE_HEADER) + sizeof(uint32_t) +
		pe_image_header->FileHeader.SizeOfOptionalHeader);
    	uint32_t i = 0;

	for (i = 0; i < pe_image_header->FileHeader.NumberOfSections; i++) {
		uint32_t pos = i;
		while ((pos > 0) && (section->PointerToRawData < section_header[pos - 1].PointerToRawData)) {
			memcpy(&section_header[pos], &section_header[pos-1], sizeof(EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		memcpy(&section_header[pos], section, sizeof(EFI_IMAGE_SECTION_HEADER));
		section += 1;
	}

    char cmdline[KERNEL_PARAMS_BUFFER_LEN] = "";
	
	for (i = 0; i < pe_image_header->FileHeader.NumberOfSections; i++) {
		section = (EFI_IMAGE_SECTION_HEADER*) &section_header[i];
		if (section->SizeOfRawData == 0)
			continue;
		
		uint8_t* base = (uint8_t*) pe_image + section->PointerToRawData;
		size_t size = (size_t) section->SizeOfRawData;
#if MEASURE_CMDLINE_DEBUG_OUT
		printf("PE %08zx - %08zx Section: %s\n", base - pe_image, base - pe_image + size, section->Name);
#endif
        if (strncmp((const char*) section->Name, ".cmdline", 8) == 0) {
            strncpy(cmdline, (const char*) base, size);
            cmdline[size] = '\0';
            break;
        }
	}
    free(section_header);

    if (!cmdline[0])
        goto cleanup;

#if MEASURE_CMDLINE_DEBUG_OUT
    printf(" %s\n", cmdline);
#endif

    munmap(pe_image, filesize);
    return kernel_params_measure1(cmdline, 0, digest);
cleanup:
    munmap(pe_image, filesize);
    return ret;
}
