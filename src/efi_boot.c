
#include "efi_boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <uchar.h>
#include <assert.h>

#include <efivar.h>

#include "defines.h"

int efi_boot_get_current(char* path, size_t len) {
    uint8_t* buffer = NULL;
    size_t size;
    uint32_t attributes;

    if (efi_get_variable(efi_guid_global, "BootCurrent", &buffer, &size, &attributes) != 0) {
        return -1;
    }

    if (size < 2) {
        return -1;
    }

    uint16_t entry = (buffer[1] << 8) | buffer[0];
    return efi_boot_get_numbered(entry, path, len);
}

int efi_boot_get_default(char* path, size_t len) {
    uint8_t* buffer = NULL;
    size_t size;
    uint32_t attributes;

    if (efi_get_variable(efi_guid_global, "BootOrder", &buffer, &size, &attributes) != 0) {
        return -1;
    }

     if (size < 2) {
        return -1;
    }

    // Just use the first entry
    uint16_t entry = (buffer[1] << 8) | buffer[0];
#if EFI_DEBUG_OUT
    fprintf(stderr, "EFI Default Boot: %04hx\n", entry);
#endif
    return efi_boot_get_numbered(entry, path, len);
}

typedef struct {
    uint8_t type;
    uint8_t subtype;
    uint16_t length;
} patial_entry_t;

int efi_boot_get_numbered(const uint16_t entry, char* path, size_t len) {
    uint8_t* buffer = NULL;
    size_t size;
    uint32_t attributes;
    char name[10];
    int ret = -1;

    mbstate_t st;
    memset(&st, 0, sizeof(st));

    snprintf(name, 10, "Boot%04hx", entry);

    if (efi_get_variable(efi_guid_global, name, &buffer, &size, &attributes) != 0) {
        return -1;
    }

    // see if the variable is long enough, to actually hold something
    if (size < sizeof(uint16_t) + sizeof(uint32_t) + 2 + 4) {
#if EFI_DEBUG_OUT
    fprintf(stderr, "EFI variable size insufficient\n");
#endif
        goto cleanup;
    }

    // skip attributes
    uint8_t *p = buffer + sizeof(uint32_t);
    uint16_t list_length  = *(uint16_t*) p;

    // skip length
    p += sizeof(uint16_t);

    if (list_length > size - (sizeof(uint32_t) + 2 + 4)) {
#if EFI_DEBUG_OUT
    fprintf(stderr, "EFI boot entry longer than variable\n");
#endif
        goto cleanup;
    }

    size_t rest_length = size - (p - buffer) - list_length;
    size_t i;
    for (i = 0; i < rest_length; i++) {
        if (i % 2 == 1) {
            if (p[i] != 0) {
                // check for invalid data, int entry name
                // is UCS-2, and entry name should be ASCII,
                // se every off byte should be 0
#if EFI_DEBUG_OUT
                fprintf(stderr, "EFI variable contains illegal UCS2-LE character\n");
#endif
                goto cleanup;
            }
        } else if (p[i] == 0) {
            // Null byte at the end
            if(p[i + 1] != 0) {
#if EFI_DEBUG_OUT
                fprintf(stderr, "EFI variable contains illegal UCS2-LE character\n");
#endif
                goto cleanup;
            }
            break;
        }
    }

    if ((i += 2) > rest_length) {
#if EFI_DEBUG_OUT
        fprintf(stderr, "EFI variable reached end of boot entry, no EFI executable path contained\n");
#endif
        goto cleanup;
    }

    p += i;
    rest_length += list_length;
    rest_length -= i;
    i = 0;
    while(rest_length - i >= 4) {
        patial_entry_t pt = {
            .type = p[i],
            .subtype = p[i + 1],
            .length = (p[i+3] << 8) | p[i+2],
        };

        if (pt.length < 4 || pt.length > rest_length) {
#if EFI_DEBUG_OUT
            fprintf(stderr, "EFI partial boot entry has illegal length\n");
#endif
            goto cleanup;
        }

        // found executable path
        if (pt.type == 0x04 && pt.subtype == 0x04) {
            size_t guessed_length = (size_t) (pt.length - 4) / 2;
            if (path != NULL && len > guessed_length) {
                const char16_t*  ucs2 = (const char16_t*) (p + (i + 4));
                size_t u8_len = 0;
                size_t c_len = 0;

                for (size_t j = 0; j < guessed_length; j++) {
                    c_len = c16rtomb(path + u8_len, ucs2[j], &st);
                    if (c_len == 0)
                        continue;
                    if (len > 0)
                        u8_len += c_len;
                    else
                        break;
                    assert(u8_len < len);
                }
                ret = u8_len;
            } else {
                // just guess, it's true for ASCII
                ret = guessed_length;
            }
            goto cleanup;
        }

        // some other entry
        i += pt.length;
    }

cleanup:
    free(buffer);
    return ret;

}
