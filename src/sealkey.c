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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <keyutils.h>

#include "configfile.h"
#include "pcr.h"
#include "measure_pe.h"
#include "measure_cmdline.h"
#include "efi_boot.h"
#include "systemd-boot.h"
#include "tpm12_types.h"
#include "tpm12_chain.h"
#include "util.h"
#include "defines.h"

#if USE_TSPI
#include "tcsp.h"
#endif

const tpm_hash_t EV_SEPERATOR = { _EV_SEPERATOR };

/**
 * Bootloader entry
 */
typedef struct {
    /**
     * Path to EFI Partition mount point
     */
    char esp[LOADER_ENTRY_PATH_LEN];

    /**
     * Relative path to the Kernel Image
     */
    char image_name[LOADER_ENTRY_PATH_LEN];

    /**
     * Options as defined in the configuration, missing initrd= flags
     */
    char options[KERNEL_PARAMS_BUFFER_LEN];

    /**
     * Number of initrd statements
     */
    uint8_t number_of_initrds;

    /**
     * Array of initrd, relative paths
     */
    char** initrd;
} bootloader_entry_t;

/**
 * Read configuration for boot loader
 */
static bool bootloader_load_config(json_object_t sub_conf, bootloader_entry_t* entry) {
    assert(sub_conf);
    assert(entry);
    // assume uninitialized
    assert(entry->initrd == NULL);

    bool ret = false;

    json_object_t bootloader_type;
    if(!json_object_object_get_ex(sub_conf, "type", &bootloader_type)) {
        fprintf(stderr, "Error: type field missing for bootloader\n");
        return false;
    }
    if (json_object_get_type(bootloader_type) != json_type_string) {
        fprintf(stderr, "Error: type field for bootloader is not a string\n");
        return false;
    }

    const char* type = json_object_get_string(bootloader_type);
    if (strcmp("systemd-boot", type) != 0) {
        fprintf(stderr, "Error: bootloader type = '%s' not supported\n", type);
        return false;
    }

    json_object_t esp;
    if(!json_object_object_get_ex(sub_conf, "esp", &esp)) {
        strcpy(entry->esp, EFI_SYSTEM_PARTITION_MOUNT_POINT);
    } else {
        if (json_object_get_type(esp) != json_type_string) {
            fprintf(stderr, "Error: type field for esp is not a string\n");
            return false;
        }
        strncpy(entry->esp, json_object_get_string(esp), sizeof(entry->esp));
    }

    json_object_t boot_entry;
    if(!json_object_object_get_ex(sub_conf, "entry", &boot_entry)) {
        fprintf(stderr, "Error: entry field missing for bootloader\n");
        return false;
    }

    if (json_object_get_type(boot_entry) != json_type_string) {
        fprintf(stderr, "Error: entry field for bootloader is not a string\n");
        return false;
    }

    const char* entry_name = json_object_get_string(boot_entry);
    char config_path[LOADER_ENTRY_PATH_LEN];
    snprintf(config_path, LOADER_ENTRY_PATH_LEN, "%s/loader/entries/%s.conf", entry->esp, entry_name);

#if SEALKEY_DEBUG_OUT
    fprintf(stderr, "Using %s as bootloader entry\n", config_path);
#endif

    char* loader_config = NULL;
    if (!systemd_boot_open(config_path, &loader_config)) {
        fprintf(stderr, "Error: Could not load loader configuration: %s\n", config_path);
        return false;
    }

    if (systemd_boot_parse_option(loader_config, NULL, "linux", entry->image_name) <= 0) {
        fprintf(stderr, "Error: No entry linux in configuration: %s\n", config_path);
        goto cleanup;
    }

    char tmp[KERNEL_PARAMS_BUFFER_LEN];
    int len = 0;
    char* pos = NULL;

    entry->initrd = NULL;
    entry->number_of_initrds = 0;
    while ((len = systemd_boot_parse_option(loader_config, &pos, "initrd", tmp)) > 0) {
        if (entry->initrd == NULL) {
            entry->number_of_initrds = 1;
            entry->initrd = malloc(sizeof(char*));
            entry->initrd[0] = malloc(len + 1);
        } else {
            entry->initrd = realloc(entry->initrd, sizeof(char*) *  (entry->number_of_initrds + 1));
            entry->initrd[entry->number_of_initrds] = malloc(len + 1);
            entry->number_of_initrds += 1;
        }
        strncpy(entry->initrd[entry->number_of_initrds - 1], tmp, len);
        entry->initrd[entry->number_of_initrds - 1][len] = '\0';
    }

    if (systemd_boot_parse_option(loader_config, NULL, "options", entry->options) <= 0)
        entry->options[0] = '\0';

    ret = true;

cleanup:
    free(loader_config);
    return ret;
}

/**
 * Free allocated memory in the bootloader entry struct
 */
static void bootloader_free_config(bootloader_entry_t* entry) {
    assert(entry);

    if (entry->initrd) {
        for (uint8_t i = 0; i < entry->number_of_initrds; i++) {
            free(entry->initrd[i]);
        }
        free(entry->initrd);
        entry->number_of_initrds = 0;
        entry->initrd = NULL;
    }
}

/**
 * Hash sequence of PE32+ EFI applications for PCR 4
 */
static inline bool calculate_load_image_array(json_object_t array, bootloader_entry_t* entry, tpm_hash_t* chained_digest) {
    assert(array);
    assert(chained_digest);

    int length = json_object_array_length(array);

    TPM12_Chain_Context chain_ctx;
    TPM12_Chain_Init(&chain_ctx);
    
    // Chain seperator to initialize array, no Firmware hashes must be logged in PCR 4
    TPM12_Chain_Update(&chain_ctx, &EV_SEPERATOR);

    for (int i = 0; i < length; i++) {
        json_object_t array_val = json_object_array_get_idx(array, i);
        if (json_object_get_type(array_val) != json_type_string) {
            fprintf(stderr, "Error: value in paths array is not a string\n");
            return false;
        }

        const char* relative_filename = json_object_get_string(array_val);
        if (relative_filename == NULL) {
            fprintf(stderr, "Error: value in paths array is not a string\n");
            return false;
        }

        char filename[LOADER_ENTRY_PATH_LEN];
        if (entry == NULL) {
            if (strcasecmp("$linux", relative_filename) == 0) {
                fprintf(stderr, "Error: $linux requested, but no bootloader configuration provided\n");
                return false;
            } else {
                if (relative_filename[0] == '/') {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s%s", EFI_SYSTEM_PARTITION_MOUNT_POINT, relative_filename);
                } else {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s/%s", EFI_SYSTEM_PARTITION_MOUNT_POINT, relative_filename);
                }
            }
        } else {
            if (strcasecmp("$linux", relative_filename) == 0) {
                if (entry->image_name[0] == '\0') {
                    fprintf(stderr, "Error: $linux requested, but bootloader configuration did not provide image name\n");
                    return false;
                }
                if (entry->image_name[0] == '/') {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s%s", entry->esp, entry->image_name);
                } else {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s/%s", entry->esp, entry->image_name);
                }
            } else if (strncasecmp("$efiboot:", relative_filename, 9) == 0) {
                char* p = strchr(relative_filename, ':') + 1;
                if (*p != '\0') {
                    char path[LOADER_ENTRY_PATH_LEN];
                    size_t len = sizeof(path);
                    int ret;

                    if (strcasecmp("default", p) == 0) {
                        ret = efi_boot_get_default(path, len);
                    } else if (strcasecmp("current", p) == 0) {
                        ret = efi_boot_get_current(path, len);
                    } else {
                        char* r;
                        int entry = strtol(p, &r, 16);
                        if (entry == 0 && r == p) {
                            fprintf(stderr, "Error: Cannot parse $efiboot entry: %s\n", p);
                            return false;
                        }
                        
                        ret = efi_boot_get_numbered(entry, path, len);
                    }

                    if (ret < 0) {
                        fprintf(stderr, "Error: Cannot read $efiboot from efivars\n");
                        return false;
                    }

                    assert((size_t) ret < sizeof(path));

                    char* p = path;
                    while((p = strchr(p, '\\')) != NULL)
                        *p = '/';
                    
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s%s", entry->esp, path);
                } else {
                    fprintf(stderr, "Error: Illegal $efiboot entry\n");
                    return false;
                }
            } else {
                if (relative_filename[0] == '/') {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s%s", entry->esp, relative_filename);
                } else {
                    snprintf(filename, LOADER_ENTRY_PATH_LEN, "%s/%s", entry->esp, relative_filename);
                }
            }
        }

        tpm_hash_t digest;
        if (!pe_image_measure1(filename, &digest)) {
            fprintf(stderr, "Error: Could not calculate PE32+ image hash: %s\n", filename);
            return false;
        }

        TPM12_Chain_Update(&chain_ctx, &digest);
    }

    TPM12_Chain_Finalize(&chain_ctx, chained_digest);

    return true;
}

/**
 * Hash kernel options the same way systemd-boot would
 */
static inline bool calculate_boot_options(bootloader_entry_t* entry, bool initrd_hash, tpm_hash_t* chained_digest) {
    
    if (entry == NULL) {
        fprintf(stderr, "Error: Cannot create digest for commandline without bootloader configuration\n");
        return false;
    }

    assert(chained_digest);

    // no commandline means no digest
    if (entry->options[0] == '\0' && entry->number_of_initrds == 0) {
        return true;
    }

    TPM12_Chain_Context ctx;
    TPM12_Chain_Init(&ctx);

    char tmp[LOADER_ENTRY_PATH_LEN];
    tpm_hash_t md;

    int len = 0;
    char option[KERNEL_PARAMS_BUFFER_LEN];
    char* result = option;
    int offset = 0;
    // prepend initrd to commandline
    for (int i = 0; i < entry->number_of_initrds; i++) {
        len = KERNEL_PARAMS_BUFFER_LEN - 7 - strlen(entry->initrd[i]) - offset;
        offset += snprintf(result + offset, len, "initrd=%s ", entry->initrd[i]);
    }

    // initrd are passed as EFI file paths, relative to ESP root
    // so all / are infact \ (see /proc/cmdline)
    for (char* iter = result; iter - result < offset && *iter != 0; iter++) {
        if (*iter == '/')
            *iter = '\\';
    }

    // no normal kernel options set, only initrd
    // remove last space
    if (entry->options[0] == '\0') {
        option[offset - 1] = '\0';
    }

    len = KERNEL_PARAMS_BUFFER_LEN - offset;
    strncpy(result + offset, entry->options, len);

    if (!kernel_params_measure1(option, &md)) {
        fprintf(stderr, "Error: Could not calculate boot options digest\n");
        return false;
    }

    TPM12_Chain_Update(&ctx, &md);    

    if (initrd_hash && entry->number_of_initrds > 0) {
        for (int i = 0; i < entry->number_of_initrds; i++) {
            if (entry->initrd[i][0] == '/')
                snprintf(tmp, LOADER_ENTRY_PATH_LEN, "%s%s", entry->esp, entry->initrd[i]);
            else
                snprintf(tmp, LOADER_ENTRY_PATH_LEN, "%s/%s", entry->esp, entry->initrd[i]);
            if (!initrd_measure1(tmp, &md) ) {
                fprintf(stderr, "Error: Could not calculate hash for: %s\n", tmp);
                return false;
            }
            TPM12_Chain_Update(&ctx, &md);
        }
    }

    
    TPM12_Chain_Finalize(&ctx, chained_digest);

    return true;
}

/**
 * Set a PCR value from SHA1 hex string
 */
static bool set_pcr_from_string(const char* hex, tpm_hash_t* digest) {
    memset(digest, 0, TPM12_HASH_LEN);
    uint8_t* d = (uint8_t*) digest;

    if (strlen(hex) != TPM12_HASH_LEN * 2) {
        fprintf(stderr, "Error: Cannot set PCR form string, length is not of a SHA-1 digest (20 hex bytes)\n");
        return false;
    }

    if (sscanf(hex, TPM12_HASH_FORMAT_STRING,
        &d[0],  &d[1],  &d[2],  &d[3],  &d[4],  &d[5],  &d[6],  &d[7],  &d[8],  &d[9],
        &d[10], &d[11], &d[12], &d[13], &d[14], &d[15], &d[16], &d[17], &d[18], &d[19]) != TPM12_HASH_LEN) {
            fprintf(stderr, "Error: Cannot set PCR form string\n");
            return false;
    }

    return true;
}

/**
 * Calculate PCR for one PCR entry in configuration file
 *
 * @param[in] sub_conf
 *       JSON object of the entry in the configuration file
 * @param[in] pcr
 *       Index of the PCRs
 * @param[in,out] ctx
 * @param[in] entry
 *       Optional bootloader configuration
 */
static bool calculate_pcrs_object(json_object_t sub_conf, int pcr, pcr_ctx_t* ctx, bootloader_entry_t* entry) {
    assert(sub_conf);
    assert(ctx);
    assert(pcr >= 0 && pcr < PCR_LENGTH);

    json_object_t pcr_cfg_type;
    if(!json_object_object_get_ex(sub_conf, "type", &pcr_cfg_type)) {
        fprintf(stderr, "Error: type field missing for PCR[%02d]\n", pcr);
        return false;
    }
    if (json_object_get_type(pcr_cfg_type) != json_type_string) {
        fprintf(stderr, "Error: type field for PCR[%02d] is not a string\n", pcr);
        return false;
    }

    const char* type = json_object_get_string(pcr_cfg_type);
    if (strcmp("load-image", type) == 0) {
        json_object_t array;
        if(!json_object_object_get_ex(sub_conf, "paths", &array)) {
            fprintf(stderr, "Error: paths missing from load-image type\n");
            return false;
        }

        if (json_object_get_type(array) != json_type_array) {
            fprintf(stderr, "Error: paths in load-image type, is not an array\n");
            return false;
        }

        if (!calculate_load_image_array(array, entry, &ctx->pcrs[pcr])) {
            return false;
        }
    } else if (strcmp("entry-cmdline", type) == 0) {
        bool hash_initrd = false;
        json_object_t initrd;
        if(json_object_object_get_ex(sub_conf, "initrd", &initrd)) {
            if (json_object_get_type(initrd) != json_type_boolean) {
                fprintf(stderr, "Error: initrd in entry-cmdline type, is not a bool\n");
                return false;
            }

            hash_initrd = json_object_get_boolean(initrd);
        }

        if (!calculate_boot_options(entry, hash_initrd, &ctx->pcrs[pcr])) {
            return false;
        }

    } else if (strcmp("pcr", type) == 0) {
        json_object_t value;
        if(json_object_object_get_ex(sub_conf, "value", &value)) {
            if (json_object_get_type(value) != json_type_string) {
                fprintf(stderr, "Error: value in pcr entry, is not a string\n");
                return false;
            }

            const char* value_hex = json_object_get_string(value);
            if (!set_pcr_from_string(value_hex, &ctx->pcrs[pcr]))
                return false;
            
        }
    } else {
        fprintf(stderr, "Error: type field for PCR[%02d] is unknown: '%s'\n", pcr, type);
        return false;
    }

    return true;
}

/**
 * Mark PCR in selected PCR bit mask
 */
static inline void add_pcr_to_composite(uint16_t pcr, uint16_t* selected) {
    *selected |= (1 << pcr);
}

/**
 * Calculate and replace PCRs according to configuration in PCR context
 *
 * @param[in] configuration
 * @param[in,out] ctx
 *       PCR Context, contains PCRs read from firmware, some might be replaced, with
 *       hashes caluclated according to configuration
 * @param[out] selected_pcrs
 *       Bitmap that marks the selected PCRs according to configuration
 */
static bool calculate_pcrs(json_object_t configuration, pcr_ctx_t* ctx, uint16_t* selected_pcrs) {
    bootloader_entry_t loader_conf;
    memset(&loader_conf, 0, sizeof loader_conf);
    bootloader_entry_t* loader_conf_p = &loader_conf;
    bool ret = false;

    json_object_t bootloader;
    if (json_object_object_get_ex(configuration, "bootloader", &bootloader)) {
        bootloader_load_config(bootloader, loader_conf_p);
    } else {
        loader_conf_p = NULL;
    }

    json_object_t pcr_lock;
    if (!json_object_object_get_ex(configuration, "pcrlock", &pcr_lock)) {
        fprintf(stderr, "Error: No PCR lock configuration\n");
        goto cleanup;
    } else {
        if (json_object_get_type(pcr_lock) != json_type_object) {
            fprintf(stderr, "Error: PCR lock configuration is not a JSON object\n");
            goto cleanup;
        }

        struct json_object_iterator end = json_object_iter_end(pcr_lock);
        for (struct json_object_iterator iter = json_object_iter_begin(pcr_lock); !json_object_iter_equal(&iter, &end); json_object_iter_next(&iter)) {
            const char* name = json_object_iter_peek_name(&iter);
            struct json_object* pcr_val = json_object_iter_peek_value(&iter);
            int pcr = strtol(name, NULL, 10);
            if (pcr < 0 || pcr >= PCR_LENGTH) {
                fprintf(stderr, "Error: Invalid PCR[%02d] for lock selected\n", pcr);
                goto cleanup;
            }

            enum json_type type = json_object_get_type(pcr_val);
            switch (type) {
                case json_type_string:
                    if (strcmp("pcr", json_object_get_string(pcr_val)) == 0) {
                        add_pcr_to_composite(pcr, selected_pcrs);
                    } else {
                        const char* value_hex = json_object_get_string(pcr_val);
                        if (!set_pcr_from_string(value_hex, &ctx->pcrs[pcr])) {
                            fprintf(stderr, "Error: Invalid configuration value for PCR[%02d]: %s\n", pcr, json_object_get_string(pcr_val));
                            goto cleanup;
                        } else {
                            add_pcr_to_composite(pcr, selected_pcrs);
                        }
                    }
                    break;
                case json_type_object:
                    if (calculate_pcrs_object(pcr_val, pcr, ctx, loader_conf_p)) {
                        add_pcr_to_composite(pcr, selected_pcrs);
                    } else {
                        goto cleanup;
                    }
                    break;
                default:
                    fprintf(stderr, "Error: Invalid JSON type for PCR[%02d]: %s\n", pcr, json_type_to_name(type));
                    goto cleanup;
                    break;
            }
        }
    }

    ret = true;
cleanup:
    if (loader_conf_p != NULL)
        bootloader_free_config(loader_conf_p);
    return ret;
}

/**
 * Generate a hex string of the `PCR_INFO` struct accoring to configuration
 *
 * @param[in] configuration
 * @param[out] pcrinfo
 */
static bool generate_pcr_info_struct(json_object_t configuration, char* pcrinfo) {
	bool ret = false;
    pcr_ctx_t pcr_ctx;
    uint16_t selected_pcrs = 0;

    if (!pcr_ctx_from_system(&pcr_ctx)) {
        fprintf(stderr, "Could not read PCRs\n");
        goto cleanup;
    }

    if (!calculate_pcrs(configuration, &pcr_ctx, &selected_pcrs)) {
        goto cleanup;
    }

#if SEALKEY_DEBUG_OUT
    for (int i = 0; i < PCR_LENGTH; i++) {
        printf("NCR[%02d] ", i);
        print_md(&pcr_ctx.pcrs[i]);
        printf("\n");
    }
#endif

    pcr_composite_ctx_t composite;
    pcr_composite_init(&composite);

	for (int i = 0; i < PCR_LENGTH; i++) {
		if (selected_pcrs & (1 << i)) {
    	    pcr_composite_set(&composite, i, &pcr_ctx.pcrs[i]);
		}
	}
	
    pcr_composite_get_info_hex(&composite, pcrinfo);
	ret = true;

cleanup:
	return ret;
}

/**
 * Create a PCR info struct and seal a new key
 */
static key_serial_t seal_new_key(json_object_t configuration) {
    assert(configuration);

	key_serial_t key_num = -1;
	uint8_t key_length = 0;
    const char* key_name = NULL;
    char key_name_defaul[] = "kmk";

    json_object_t key_configuration;
    if (!json_object_object_get_ex(configuration, "key", &key_configuration)) {
        fprintf(stderr, "Error: No Key configuration\n");
        return -1;
    } else {
        if (json_object_get_type(key_configuration) != json_type_object) {
            fprintf(stderr, "Error: Key configuration is not a JSON object\n");
            return -1;
        }

        json_object_t name_cfg;
        if (!json_object_object_get_ex(key_configuration, "name", &name_cfg)) {
            fprintf(stderr, "Warning: No Key name in configuration\n");
            fprintf(stderr, "Using defaul of '%s'\n", key_name_defaul);
            key_name = key_name_defaul;
        } else {
            key_name = json_object_get_string(name_cfg);
            if (key_name == NULL) {
                fprintf(stderr, "Error: Key name is not a string\n");
                return -1;
            }
            if (strlen(key_name) == 0) {
                fprintf(stderr, "Error: Key name is an empty string\n");
                return -1;
            }
        }

        json_object_t size_cfg;
        if (!json_object_object_get_ex(key_configuration, "size", &size_cfg)) {
            fprintf(stderr, "Warning: No Key size in configuration\n");
            fprintf(stderr, "Using defaul of 64\n");
            key_length = 64;
        } else {
            if (json_object_get_type(size_cfg) != json_type_int) {
                fprintf(stderr, "Error: Key size is not an integer\n");
                return -1;
            }
            int len = json_object_get_int(size_cfg);
            if (len < 32 || len > 128) {
                fprintf(stderr, "Error: Key size invalid\n");
                return -1;
            } else {
                key_length = (uint8_t) len;
            }
        }
    }
	
	const uint32_t len = 1024;
	char parameters[1024];
	memset(parameters, 0, len);
	
	char pcrinfo_hex[128];
	memset(pcrinfo_hex, 0, 128);

	if (!generate_pcr_info_struct(configuration, pcrinfo_hex)) {
		return -1;
	}
	
	snprintf(parameters, len, "new %d pcrinfo=%s", key_length, pcrinfo_hex);
#if SEALKEY_DEBUG_OUT
	fprintf(stderr, "> keyctl add trusted %s \"%s\" @u\n", key_name, parameters);
#endif
	key_num = add_key("trusted", "kmk", parameters, strlen(parameters), KEY_SPEC_USER_KEYRING);
	
	if (key_num == -1) {
        if (errno == ENODEV) {
            fprintf(stderr, "Error: Check if the kernel module 'trusted' is loaded.\n");
        }
		fprintf(stderr, "Error: add_key: %m\n");
		return -1;
	} else {
		//printf("%d\n", key_num);
		return key_num;
	}
}

static inline void print_key(FILE* out, key_serial_t id) {
	void* buffer;
	keyctl_read_alloc(id, &buffer);
	
	fprintf(out, "%s", (char*) buffer);
	
	free(buffer);
}

/**
 * Create a sealed key accoring to configuration
 *
 * If `outfile` is not `NULL`, write the key to the specified file
 */
static inline bool new_command(json_object_t configuration, char* outfile) {
    assert(configuration);

    key_serial_t key_id = -1;

    key_id = seal_new_key(configuration);
    
    if (key_id > 0) {
        printf("%d\n", key_id);

        if (outfile != NULL) {
            FILE* out = NULL;
            out = fopen(outfile, "w");
            if (out == NULL) {
                fprintf(stderr, "Error open: %m\n");
                return false;
            }
            print_key(out, key_id);
            fclose(out);
        }

        return true;
    }
    
    return false;
}

/**
 * Reseal an existing key with updated PCR information
 *
 * If `outfile` is not `NULL`, write the key to the specified file
 */
static inline key_serial_t update_command(json_object_t configuration, char* outfile) {
    assert(configuration);

    key_serial_t key_id = -1;
    const char* key_name = NULL;
    char key_name_defaul[] = "kmk";
    json_object_t key_configuration;
    if (!json_object_object_get_ex(configuration, "key", &key_configuration)) {
        fprintf(stderr, "Error: No Key configuration\n");
        return false;
    } else {
        if (json_object_get_type(key_configuration) != json_type_object) {
            fprintf(stderr, "Error: Key configuration is not a JSON object\n");
            return false;
        }

        json_object_t name_cfg;
        if (!json_object_object_get_ex(key_configuration, "name", &name_cfg)) {
            fprintf(stderr, "Warning: No Key name in configuration\n");
            fprintf(stderr, "Using defaul of '%s'\n", key_name_defaul);
            key_name = key_name_defaul;
        } else {
            key_name = json_object_get_string(name_cfg);
            if (key_name == NULL) {
                fprintf(stderr, "Error: Key name is not a string\n");
                return false;
            }
            if (strlen(key_name) == 0) {
                fprintf(stderr, "Error: Key name is an empty string\n");
                return false;
            }
        }
    }

    key_id = keyctl_search(KEY_SPEC_USER_KEYRING, "trusted", key_name, 0);
    if (key_id == -1) {
        fprintf(stderr, "No key named '%s' in user's keyring: %m\n", key_name);
        return false;
    }

    const uint32_t len = 1024;
    char parameters[1024];
	memset(parameters, 0, len);
	
	char pcrinfo_hex[128];
	memset(pcrinfo_hex, 0, 128);

	if (!generate_pcr_info_struct(configuration, pcrinfo_hex)) {
		return false;
	}
	
	snprintf(parameters, len, "update pcrinfo=%s", pcrinfo_hex);
#if SEALKEY_DEBUG_OUT
	fprintf(stderr, "> keyctl update %d \"%s\" @u\n", key_id, parameters);
#endif
	if (keyctl_update(key_id, parameters, strlen(parameters)) != 0) {
        fprintf(stderr, "Error keyctl_update: %m\n");
        return false;
    }

    if (outfile != NULL) {
        FILE* out = NULL;
        out = fopen(outfile, "w");
        if (out == NULL) {
            fprintf(stderr, "Error open: %m\n");
            return false;
        }
        print_key(out, key_id);
        fclose(out);
    }

    printf("%d\n", key_id);

    return true;
}

/**
 * Just generate the `PCR_INFO` struct in hex format
 *
 * This is format is suitable to create/update a key from commandline
 * with `keyctl` and the `pcrinfo=` option
 *
 *~~~~~~~~~~~~~{.sh}
 * keyctl add trusted <keyname> "new 64 pcrinfo=$(< pcr.hex)"
 *
 * keyctl update <keyid> "update pcrinfo=$(< pcr.hex)"
 *~~~~~~~~~~~~~
 * 
 * Where pcr.hex is the file provided by outfile.
 *
 * For more information see:
 * [https://www.kernel.org/doc/Documentation/security/keys-trusted-encrypted.txt]
 */
static inline bool pcrinfo_command(json_object_t configuration, char* outfile) {
    assert(configuration);

	char pcrinfo_hex[128];
	memset(pcrinfo_hex, 0, 128);

	if (!generate_pcr_info_struct(configuration, pcrinfo_hex)) {
		return false;
	}

    if (outfile != NULL) {
        FILE* out = NULL;
        out = fopen(outfile, "w");
        if (out == NULL) {
            fprintf(stderr, "Error open: %m\n");
            return false;
        }
        fprintf(out, "%s", pcrinfo_hex);
        fclose(out);
    } else {
        printf("%s\n", pcrinfo_hex);
    }

    return true;
}

/**
 * Print a list of all PCR locks in configfile as they are currently in the firmware.
 */
static inline bool pcr_current_command(json_object_t configuration) {
    assert(configuration);

    pcr_ctx_t pcr_ctx;
    uint16_t selected_pcrs = 0;

    if (!pcr_ctx_from_system(&pcr_ctx)) {
        fprintf(stderr, "Could not read PCRs\n");
        return false;
    }

    json_object_t pcr_lock;
    if (!json_object_object_get_ex(configuration, "pcrlock", &pcr_lock)) {
        fprintf(stderr, "Error: No PCR lock configuration\n");
        return false;
    } else {
        if (json_object_get_type(pcr_lock) != json_type_object) {
            fprintf(stderr, "Error: PCR lock configuration is not a JSON object\n");
            return -1;
        }

        struct json_object_iterator end = json_object_iter_end(pcr_lock);
        for (struct json_object_iterator iter = json_object_iter_begin(pcr_lock); !json_object_iter_equal(&iter, &end); json_object_iter_next(&iter)) {
            const char* name = json_object_iter_peek_name(&iter);
            int pcr = strtol(name, NULL, 10);
            if (pcr < 0 || pcr >= PCR_LENGTH) {
                fprintf(stderr, "Error: Invalid PCR[%02d] for lock selected\n", pcr);
                return false;
            }

            add_pcr_to_composite(pcr, &selected_pcrs);
        }
    }

    for (int i = 0; i < PCR_LENGTH; i++) {
		if (selected_pcrs & (1 << i)) {
            printf("PCR[%02d] ", i);
            print_md(&pcr_ctx.pcrs[i]);
            printf("\n");
        }
    }

    return true;
}

/**
 * Print a list of all PCR locks as they are configured (calculated)
 */
static inline bool pcr_updated_command(json_object_t configuration) {
    assert(configuration);

    pcr_ctx_t pcr_ctx;
    uint16_t selected_pcrs = 0;

    if (!pcr_ctx_from_system(&pcr_ctx)) {
        fprintf(stderr, "Could not read PCRs\n");
        return false;
    }

    if (!calculate_pcrs(configuration, &pcr_ctx, &selected_pcrs)) {
        return false;
    }

    for (int i = 0; i < PCR_LENGTH; i++) {
		if (selected_pcrs & (1 << i)) {
            printf("PCR[%02d] ", i);
            print_md(&pcr_ctx.pcrs[i]);
            printf("\n");
        }
    }

    return true;
}

#if USE_TSPI
/**
 * Seal a file in the TPM tools format, so that tpm_unseal can open it.
 *
 * This differs from tpm_seal, in that, we actually calculate new PCRs,
 * according to the configuration file
 *
 * @param configuration
 * @param infile
 *        can be `NULL` in wich case `stdin` will be used
 * @param outfile
 *        can be `NULL` in which case `stdout` will be used
 */
static inline bool tpm_seal_command(json_object_t configuration, const char* infile, const char* outfile) {
    assert(configuration);

    pcr_ctx_t pcr_ctx;
    uint16_t selected_pcrs = 0;

    if (!pcr_ctx_from_system(&pcr_ctx)) {
        fprintf(stderr, "Could not read PCRs\n");
        return false;
    }

    if (!calculate_pcrs(configuration, &pcr_ctx, &selected_pcrs)) {
        return false;
    }

    bool ret = false;
    int fd = -1;
    ssize_t length = 0;
    uint8_t* buffer = NULL;
    ssize_t out_length = 0;
    uint8_t* out_buffer = NULL;
    if (infile != NULL) {
        if ((fd = open(infile, O_RDONLY)) < 0) {
            fprintf(stderr, "Error: open: %m\n");
            goto cleanup;
        }

        if ((length = lseek(fd, 0, SEEK_END)) < 0) {
            fprintf(stderr, "Error: seek: %m\n");
            goto cleanup;
        }

        lseek(fd, 0, SEEK_SET);

        if ((buffer = malloc(length)) == NULL) {
            fprintf(stderr, "Error: malloc: %m\n");
            goto cleanup;
        }

        if (read(fd, buffer, length) != length) {
            fprintf(stderr, "Error: read: %m\n");
            goto cleanup;
        }
    } else {
        const size_t buffer_chunk = 4096;
        uint16_t counter = 1;
        if ((buffer = malloc(buffer_chunk)) == NULL ) {
            fprintf(stderr, "Error: malloc: %m\n");
            goto cleanup;
        }
        size_t read_bytes = 0;

        while (!feof(stdin)) {
            read_bytes = fread(buffer, 1, buffer_chunk, stdin);
            if (read_bytes == buffer_chunk) {
                counter += 1;
                if ((buffer = realloc(buffer, buffer_chunk * counter)) == NULL) {
                    fprintf(stderr, "Error: malloc: %m\n");
                    goto cleanup;
                }
            } else if (read_bytes == 0) {
                if (ferror(stdin)) {
                    fprintf(stderr, "Error: read: %m\n");
                    goto cleanup;
                }
            }

            length += read_bytes;
        }
    }
    
    if ((out_length = tcsp_seal_data(buffer, length, &pcr_ctx, selected_pcrs, &out_buffer)) < 0) {
        goto cleanup;
    }

    if (outfile != NULL) {
        FILE* output;
        if ((output = fopen(outfile, "w")) == NULL) {
            fprintf(stderr, "Error: open: %m\n");
            goto cleanup;
        }
        fwrite(out_buffer, 1, out_length, output);
        fputs("\n", output);
        fclose(output);
    } else {
        fwrite(out_buffer, 1, out_length, stdout);
        fputs("\n", stdout);
    }

    ret = true;
cleanup:
    if (fd >= 0)
        close(fd);
    if (buffer)
        free(buffer);
    if (out_buffer)
        free(out_buffer);

    return ret;
}
#endif // USE_TSPI

#if USE_TSPI
/**
 * Unseal a file in the TPM tools format and reseal it using newly calculated PCRs
 *
 * This function uses library calls for unsealing, as these are provided by tpm_tools.
 *
 * @param configuration
 * @param infile
 * @param outfile
 *        can be `NULL` in which case `stdout` will be used
 */
static inline bool tpm_update_command(json_object_t configuration, const char* infile, const char* outfile) {
    assert(infile);
    assert(configuration);

    bool ret = false;
    ssize_t length = 0;
    uint8_t* buffer = NULL;
    ssize_t out_length = 0;
    uint8_t* out_buffer = NULL;

    if ((length = tcsp_unseal_data(infile, &buffer)) < 0) {
        goto cleanup;
    }

    pcr_ctx_t pcr_ctx;
    uint16_t selected_pcrs = 0;

    if (!pcr_ctx_from_system(&pcr_ctx)) {
        fprintf(stderr, "Could not read PCRs\n");
        goto cleanup;
    }

    if (!calculate_pcrs(configuration, &pcr_ctx, &selected_pcrs)) {
        goto cleanup;
    }

    if ((out_length = tcsp_seal_data(buffer, length, &pcr_ctx, selected_pcrs, &out_buffer)) < 0) {
        goto cleanup;
    }

    if (outfile != NULL) {
        FILE* output;
        if ((output = fopen(outfile, "w")) == NULL) {
            fprintf(stderr, "Error: open: %m\n");
            goto cleanup;
        }
        fwrite(out_buffer, 1, out_length, output);
        fputs("\n", output);
        fclose(output);
    } else {
        fwrite(out_buffer, 1, out_length, stdout);
        fputs("\n", stdout);
    }

    ret = true;
cleanup:
    if (buffer)
        free(buffer);
    if (out_buffer)
        free(out_buffer);
    
    return ret;
}
#endif // USE_TSPI

static inline void print_usage() {
    printf(
        PROGRAM_NAME " " PROGRAM_VERSION"\n"
        "\n"
        PROGRAM_NAME " new <configfile> [<outfile>]\n"
        "   Create a new key with specified configuration\n"
        "\n"
        PROGRAM_NAME " update <configfile> [<outfile>]\n"
        "   Update an exisiting key with specified configuration\n"
        "\n"
#if USE_TSPI
        PROGRAM_NAME " tpm_seal <configfile> [<inputfile>] [<outfile>]\n"
        "   Seal a new file with PCR configuration\n"
        "\n"
        PROGRAM_NAME " tpm_update <configfile> <inputfile> [<outfile>]\n"
        "   Update the seal on an exisiting encrypted file with PCR configuration\n"
        "\n"
#endif // USE_TSPI
        PROGRAM_NAME " pcrinfo <configfile> [<outfile>]\n"
        "   Just generate the PCR_INFO struct, suitable for calling keyctl\n"
        "\n"
        PROGRAM_NAME " pcr current <configfile>\n"
        "   Show selected PCRs from the System's Firmware (read from /sys/class/tpm/tpm0)\n"
        "\n"
        PROGRAM_NAME " pcr updated <configfile>\n"
        "   Show selected the PCRs according to configfile\n"
        "\n"
        PROGRAM_NAME " help\n"
        "   Prints this help message\n"
        "\n"
        "Configuration file JSON format:\n"
        "  {\n"
        "    \"key\": { \"name\": \"kmk\", \"size\": 32 },\n"
        "    \"bootloader\": { \"type\": \"systemd-boot\", \"entry\": \"linux\" },\n"
        "    \"pcrlock\": {\n"
        "      \"0\": { \"type\": \"pcr\" },\n"
        "      \"4\": { \"type\": \"load-image\", \"paths\": [ \"$efiboot:default\", \"$linux\" ] },\n"
        "      \"8\": { \"type\": \"entry-cmdline\" }\n"
        "    }\n"
        "  }\n"
        "\n"
        "The \"key\" section describes key name and length for newly created keys and key updates\n"
        "  Keys are created in kernel, the kernel module trusted.ko must be loaded. Keys can be\n"
        "  inspected using the keyctl utility.\n"
        "The \"bootloader\" section defines the systemd-boot entry used for getting the kernel\n"
        "   cmdline and path for the kernel image.\n"
        "   Optinally the ESP path can be changed with \"esp\" it defaults to \"/boot\".\n"
        "The \"pcrlock\" section lists PCRs for sealing the key, the following types are recognized:\n"
        "  \"pcr\" read the PCR from the Firmware and use it for sealing\n"
        "  \"load-image\" create PCR 4 hash from the list in \"paths\", \n"
        "     \"$linux\" refers to the kernel, \"$efiboot:{default,current,XXXX}\" to a EFI boot entry\n"
        "  \"entry-cmdline\" create hash the same way systemd-boot creates PCR 8 from kernel parameters\n");
}

int main(int argc, char* argv[]) {
    int ret = 1;

    if (argc > 2) {
            json_object_t configuration = NULL;
            int configuration_option = 2;
            if (strcmp(argv[1], "pcr") == 0) {
                if (argc > 3) {
                    configuration_option = 3;
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    return 1;
                }
            }

            if (!configfile_read(argv[configuration_option], &configuration))
                return 1;
            
            if (json_object_get_type(configuration) != json_type_object) {
                fprintf(stderr, "Error: Configuration is not a JSON object\n");
                configfile_free(configuration);
                return 1;
            }
            
            char* outfile = NULL;
            char* infile = NULL;
            if (strcmp(argv[1], "new") == 0) {
                if (argc == 4) {
                    outfile = argv[3];
                } else if (argc == 3) {
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    goto cleanup;
                }

                if (new_command(configuration, outfile))
                    ret = 0;
            } else if (strcmp(argv[1], "update") == 0) {
                if (argc == 4) {
                    outfile = argv[3];
                } else if (argc == 3) {
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    goto cleanup;
                }

                if (update_command(configuration, outfile))
                    ret = 0;
            } else if (strcmp(argv[1], "pcrinfo") == 0) {
                if (argc == 4) {
                    outfile = argv[3];
                } else if (argc == 3) {
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    goto cleanup;
                }

                if (pcrinfo_command(configuration, outfile))
                    ret = 0;
#if USE_TSPI
            } else if (strcmp(argv[1], "tpm_seal") == 0) {
                if (argc == 5) {
                    if (strlen(argv[3]) > 0)
                        infile = argv[3];
                    if (strlen(argv[4]) > 0)
                        outfile = argv[4];
                } else if (argc == 4) {
                    if (strlen(argv[3]) > 0)
                        infile = argv[3];
                } else if (argc == 3) {
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    goto cleanup;
                }

                if (tpm_seal_command(configuration, infile, outfile))
                    ret = 0;
            } else if (strcmp(argv[1], "tpm_update") == 0) {
                if (argc == 5) {
                    infile = argv[3];
                    if (strlen(argv[4]) > 0)
                        outfile = argv[4];
                } else if (argc == 4) {
                    infile = argv[3];
                } else {
                    printf("Illegal number of arguments: %d\n", argc);
                    goto cleanup;
                }

                if (tpm_update_command(configuration, infile, outfile))
                    ret = 0;
#endif // USE_TSPI
            } else if (strcmp(argv[1], "pcr") == 0 && argc > 3) {
                if (strcmp(argv[2], "current") == 0) {
                    if (pcr_current_command(configuration))
                        ret = 0;
                } else if (strcmp(argv[2], "updated") == 0) {
                    if (pcr_updated_command(configuration))
                        ret = 0;
                } else {
                    printf("Unknown sub command: %s\n", argv[2]);
                    goto cleanup;
                }
            } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
                print_usage();
                ret = 0;
            } else {
                printf("Unknown command: %s\n", argv[1]);
                goto cleanup;
            }
    cleanup:
            //CRYPTO_cleanup_all_ex_data();
            configfile_free(configuration);
    	} else if (argc > 1) {
                if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
                print_usage();
                ret = 0;
            } else {
                printf("Unknown command: %s\n", argv[1]);
            }
        } else {
            printf("No command provided\n");
        }
	
	return ret;
}
