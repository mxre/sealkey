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

#include "measure_pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include "pe.h"
#include "util.h"
#include "hash.h"
#include "tpm12_types.h"
#include "defines.h"

// hash a PE executabale the same way LoadImage() would do in
// EFI, based on code from OVMF
bool pe_image_measure1(const char* file, tpm_hash_t* hash) {
    assert(file);
    assert(hash);

	bool ret = false;


	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: open: %m\n");
		return ret;
	}

#if 1
    struct statx* st = (struct statx*) malloc(sizeof(struct statx));
	statx(fd, "", AT_EMPTY_PATH, STATX_SIZE, st);
    size_t filesize = st->stx_size;
    free(st);
#else
    size_t filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
#endif
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
	
	//printf("%x len=%x\n", pe->data_diretories[PE_DIRECTORY_CERTIFICATE_TABLE].offset, pe->data_diretories[PE_DIRECTORY_CERTIFICATE_TABLE].length);
	
	// tianocore:/SecurityPkg/Library/DxeTpmMeasureBootLib/DxeTpmMeasureBootLib.c
	hash_ctx_t ctx = hash_create_ctx(HASH_SHA1);

	uint8_t* base;
	size_t size;
	size_t sum_of_bytes_hashed = 0;

	base = pe_image;
	// 1. Hash the image header from its base to beginning of the image checksum.
	size = ((uint8_t*) &pe_image_header->OptionalHeader.CheckSum - pe_image);
#if MEASURE_PE_DEBUG_OUT
	printf("PE %08x - %08zx Header\n", 0, size);
#endif
	hash_update(ctx, base, size);
	
	// 2. Skip over the image checksum (it occupies a single ULONG).
	if (pe_image_header->OptionalHeader.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
		// 3. Since there is no Cert Directory in optional header, hash everything
    	//    from the end of the checksum to the end of image header.
		base = (uint8_t*) &pe_image_header->OptionalHeader.CheckSum + sizeof(uint32_t);
		size = pe_image_header->OptionalHeader.SizeOfHeaders - (size_t) (base - pe_image);
#if MEASURE_PE_DEBUG_OUT
		printf("PE %08zx - %08zx Header\n", base - pe_image, base - pe_image + size);
#endif
		if (size != 0)
			hash_update(ctx, base, size);
	} else {
		// 3. Hash everything from the end of the checksum to the start of the Cert Directory.
		base = (uint8_t*) &pe_image_header->OptionalHeader.CheckSum + sizeof(uint32_t);
		size = (size_t) ((uint8_t*) &pe_image_header->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] - base);
#if MEASURE_PE_DEBUG_OUT
		printf("PE %08zx - %08zx Header\n", base - pe_image, base - pe_image + size);
#endif
		if (size != 0)
			hash_update(ctx, base, size);
		
		// 3a. Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
        // 3b. Hash everything from the end of the Cert Directory to the end of image header.
		base = (uint8_t*) &pe_image_header->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
		size = pe_image_header->OptionalHeader.SizeOfHeaders - (size_t) (base - pe_image);
#if MEASURE_PE_DEBUG_OUT
		printf("PE %08zx - %08zx Directory\n", base - pe_image, base - pe_image + size);
#endif
		if (size != 0)
			hash_update(ctx, base, size);
	}
	
	/* 4.  Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
     *     structures in the image. The 'NumberOfSections' field of the image
     *     header indicates how big the table should be. Do not include any
     *    IMAGE_SECTION_HEADERs in the table whose 'SizeOfRawData' field is zero.
     */
	EFI_IMAGE_SECTION_HEADER* section_header = malloc(pe_image_header->FileHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER));
	if (section_header == NULL) {
		fprintf(stderr, "Error malloc: %m\n");
		goto cleanup;
	}
	
	sum_of_bytes_hashed = pe_image_header->OptionalHeader.SizeOfHeaders;
	memset(section_header, 0, pe_image_header->FileHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER));
	
	 /* 5.   Using the 'PointerToRawData' in the referenced section headers as
      *      a key, arrange the elements in the table in ascending order. In other
      *      words, sort the section headers according to the disk-file offset of
      *      the section.
      */
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
	
	/* 6.  Walk through the sorted table, bring the corresponding section
     *     into memory, and hash the entire section
     */
	for (i = 0; i < pe_image_header->FileHeader.NumberOfSections; i++) {
		section = (EFI_IMAGE_SECTION_HEADER*) &section_header[i];
		if (section->SizeOfRawData == 0)
			continue;
		
		base = (uint8_t*) pe_image + section->PointerToRawData;
		size = (size_t) section->SizeOfRawData;
#if MEASURE_PE_DEBUG_OUT
		printf("PE %08zx - %08zx Section: %s\n", base - pe_image, base - pe_image + size, section->Name);
#endif
		if (size != 0)
			hash_update(ctx, base, size);
		sum_of_bytes_hashed += size;
	}
	
	free(section_header);
	
	/*  7.  If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
     *      data in the file that needs to be added to the hash. This data begins
     *      at file offset SUM_OF_BYTES_HASHED and its length is:
     *             FileSize  -  (CertDirectory->Size)
     */
	if (filesize > sum_of_bytes_hashed) {
		//printf("%zu > %zu\n", filesize, sum_of_bytes_hashed);
		base = pe_image + sum_of_bytes_hashed;
		
		uint32_t cert_size = 0;
		if (pe_image_header->OptionalHeader.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
			cert_size = pe_image_header->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		}

		if (filesize > cert_size + sum_of_bytes_hashed) {
			size = filesize - cert_size - sum_of_bytes_hashed;
#if MEASURE_PE_DEBUG_OUT
			printf("PE %08zx - %08zx Extra data after image end\n", base - pe_image, base - pe_image + size);
#endif
			hash_update(ctx, base, size);
		} else if (filesize < cert_size + sum_of_bytes_hashed) {
			fprintf(stderr, "Error: corruption in section directory\n");
			goto cleanup;
		}
	}
	
	// 8. Finalize the hash
	hash_finalize(ctx, (void*) hash, TPM12_HASH_LEN);
    hash_free_ctx(ctx);

#if MEASURE_PE_DEBUG_OUT
	print_md(hash);
    printf(" %s\n", file);
#endif

	ret = true;
cleanup:
	munmap(pe_image, filesize);
	return ret;
}
