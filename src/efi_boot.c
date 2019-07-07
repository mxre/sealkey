
#include "efi_boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uchar.h>
#include <assert.h>

#include <efivar.h>
#include <libudev.h>

#include "defines.h"

static const efi_guid_t SYSTEMD_GUID = EFI_GUID(0x4a67b082, 0x0a4c, 0x41cf, 0xb6c7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f);

static bool _ucs2_to_utf8(const char16_t* ucs2, size_t length, char* buffer, size_t* buffer_length) {
    bool ret = false;
    mbstate_t st = { 0 };

    size_t guessed_length = (size_t) length / 2;
    if (*buffer_length < guessed_length) {
        *buffer_length = guessed_length;
    } else if (buffer != NULL) {
        size_t u8_len = 0;

        for (size_t j = 0; j < guessed_length; j++) {
            size_t c_len = c16rtomb(buffer + u8_len, ucs2[j], &st);
            if (c_len == 0)
                continue;
            if (length > 0)
                u8_len += c_len;
            else
                break;
        }
        *buffer_length = u8_len;
        ret = true;
    }

    return ret;
}

/**
 * Get the mount point for a specific device.
 *
 * This only works with the kernel names from `/proc/mounts`
 */
static char* efi_boot_find_mount_path(const char* device) {
    FILE* fp = fopen("/proc/mounts", "r");
    if (!fp) {
        fprintf(stderr, "Cannot open active system mounts\n");
        return NULL;
    }

    char a[255];
    char b[255];
    char* path = NULL;
    while (!feof(fp)) { 
        if (fscanf(fp, "%s %s %*s %*s %*u %*u", (char*) &a, (char*) &b) != 2)
            continue;
        if (strcmp(a, device) == 0) {
            path = strdup(b);
            break;
        }
    }
    fclose(fp);
    return path;
}

/**
 * Make a sanity check on the EFI partition GUID
 */
static bool efi_boot_partition(efi_guid_t* guid, char* esp) {
    struct udev* udev = udev_new();
    bool ret = false;
    if (!udev) {
        fprintf(stderr, "Cannot connect to udev\n");
        return ret;
    }
    struct udev_enumerate* e = udev_enumerate_new(udev);
    if (!udev) {
        fprintf(stderr, "Cannot begin enumeration\n");
        goto cleanup_udev;
    }

    char* attr = NULL;
    efi_guid_to_str(guid, &attr);

    if (udev_enumerate_add_match_subsystem(e, "block") < 0) {
        fprintf(stderr, "Cannot add subsystem to enumeration\n");
        goto cleanup_enum;
    }
    if (udev_enumerate_add_match_property(e, "ID_PART_ENTRY_UUID", attr) < 0) {
        fprintf(stderr, "Cannot add attributes to enumeration\n");
        goto cleanup_enum;
    }
    if (udev_enumerate_scan_devices(e) < 0) {
        fprintf(stderr, "Could not run device enumeration\n");
        goto cleanup_enum;
    }

    struct udev_list_entry* list = udev_enumerate_get_list_entry(e);
    struct udev_list_entry* le;
    const char* path = NULL;
    udev_list_entry_foreach(le, list) {
        if (path) {
            fprintf(stderr, "More than one matching partition in system\n");
            goto cleanup_enum;
        }
        path = udev_list_entry_get_name(le);
    }

    struct udev_device* dev = udev_device_new_from_syspath(udev, path);
    if (!dev) {
        fprintf(stderr, "Cannot get device from /sys path\n");
        goto cleanup_enum;
    }

    path = udev_device_get_devnode(dev);
    if (!path) {
        fprintf(stderr, "Device does not hava a /dev path\n");
        goto cleanup_dev;
    }


    char* fs = efi_boot_find_mount_path(path);
    if (!fs) {
        fprintf(stderr, "Partition %s not mounted\n", attr);
        goto cleanup_dev;
    }
#if EFI_DEBUG_OUT
    fprintf(stderr, "EFI partition %s mounted at %s\n", path, fs);
#endif
    if (esp)
        strcpy(esp, fs);
    free(fs);
    ret = true;

cleanup_dev:
    udev_device_unref(dev);
cleanup_enum:
    udev_enumerate_unref(e);
    free(attr);
cleanup_udev:
    udev_unref(udev);

    return ret;
}

bool efi_boot_get_esp(char* esp) {
    uint8_t* buffer = NULL;
    size_t size;
    uint32_t attributes;

    if (efi_get_variable(SYSTEMD_GUID, "LoaderDevicePartUUID", &buffer, &size, &attributes) != 0) {
        fprintf(stderr, "Cannot find LoaderDevicePartUUID EFI variable.\n");
        return false;
    }

    size_t guid_len = 40;
    char part_guid_str[guid_len];
    if (!_ucs2_to_utf8((const char16_t*) buffer, size, part_guid_str, &guid_len)) {
        fprintf(stderr, "Cannot read LoaderDevicePartUUID EFI variable.\n");
        return false;
    }
    efi_guid_t part_guid;
    if (efi_str_to_guid(part_guid_str, &part_guid) != 0) {
        fprintf(stderr, "Cannot parse LoaderDevicePartUUID EFI variable.\n");
        return false;
    }

    efi_boot_partition(&part_guid, esp);
    return true;
}

int efi_boot_get_current(char* path, size_t len) {
    uint8_t* buffer = NULL;
    size_t size;
    uint32_t attributes;

    if (efi_get_variable(efi_guid_global, "BootCurrent", &buffer, &size, &attributes) != 0) {
        return -1;
    }

    if (size < 2) {
        free(buffer);
        return -1;
    }

    uint16_t entry = *((uint16_t*) buffer);
    free(buffer);
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
        free(buffer);
        return -1;
    }

    // Just use the first entry
    uint16_t entry = *((uint16_t*) buffer);
    free(buffer);
#if EFI_DEBUG_OUT
    fprintf(stderr, "EFI Default Boot: %04hx\n", entry);
#endif
    return efi_boot_get_numbered(entry, path, len);
}

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
                // so every other byte should be 0
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
        efidp_header* pt = (efidp_header*) (p + i);

        if (pt->length < 4 || pt->length > rest_length) {
#if EFI_DEBUG_OUT
            fprintf(stderr, "EFI partial boot entry has illegal length\n");
#endif
            goto cleanup;
        }

        if (pt->type == EFIDP_MEDIA_TYPE && pt->subtype == EFIDP_MEDIA_HD) {
            // found disk descriptor, this should be the ESP
            efidp_hd* phd = (efidp_hd*) pt;
            if (phd->format != EFIDP_HD_FORMAT_GPT) {
#if EFI_DEBUG_OUT
                fprintf(stderr, "EFI entry does not point to a GPT disk\n");
#endif
                goto cleanup;
            }
            if (phd->signature_type != EFIDP_HD_SIGNATURE_GUID) {
#if EFI_DEBUG_OUT
                fprintf(stderr, "EFI entry does not point to a GPT signature partition\n");
#endif
                goto cleanup;
            }

            efi_guid_t* part_uuid = (efi_guid_t*) phd->signature;
#if EFI_DEBUG_OUT
            char* str = NULL;
            efi_guid_to_str(part_uuid, &str);
            fprintf(stderr, "EFI entry partition: %s\n", str);
            free(str);
#endif
            efi_boot_partition(part_uuid, NULL);
        } else if (pt->type == EFIDP_MEDIA_TYPE && pt->subtype == EFIDP_MEDIA_FILE) {
            // found executable path
            if (_ucs2_to_utf8((const char16_t*) (p + (i + 4)), (pt->length - 4), path, &len)) {
                ret = (int) len;
            }
            goto cleanup;
        }

        // next entry
        i += pt->length;
    }

#if EFI_DEBUG_OUT
    if (ret < 0)
        fprintf(stderr, "EFI entry did not contain an application path\n");
#endif

cleanup:
    free(buffer);
    return ret;

}
