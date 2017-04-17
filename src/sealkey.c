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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <keyutils.h>

#include <openssl/crypto.h>

#include "configfile.h"
#include "pcr.h"
#include "measure_pe.h"
#include "measure_cmdline.h"
#include "tpm12_chain.h"
#include "util.h"

#if USE_TSPI
#include "tcsp.h"
#endif

#ifdef DEBUG
#define SEALKEY_DEBUG_OUT 1
#else
#define SEALKEY_DEBUG_OUT 0
#endif

#define PROGRAM_NAME "sealkey"
#define PROGRAM_VERSION "0.1"

/**
 * Hash sequence of PE32+ EFI applications for PCR 4
 */
static inline bool calculate_load_image_array(json_object_t array, tpm_hash_t* chained_digest) {
    assert(array);
    assert(chained_digest);

    int length = json_object_array_length(array);

    TPM12_Chain_Context chain_ctx;
    TPM12_Chain_Init(&chain_ctx);
    
    // hash of the EV_SEPERATOR in accoring to TCG EFI Platform 1.22 specs
    // this is the hash of 0 as a uint32_t
    uint8_t init_hash[] = { 0x90, 0x69, 0xca, 0x78, 0xe7, 0x45, 0x0a, 0x28, 0x51, 0x73, 0x43, 0x1b, 0x3e, 0x52, 0xc5, 0xc2, 0x52, 0x99, 0xe4, 0x73 };
    TPM12_Chain_Update(&chain_ctx, (tpm_hash_t*) init_hash);

    for (int i = 0; i < length; i++) {
        json_object_t array_val = json_object_array_get_idx(array, i);
        if (json_object_get_type(array_val) != json_type_string) {
            fprintf(stderr, "Error: value in paths array is not a string\n");
            return false;
        }

        const char* filename = json_object_get_string(array_val);
        if (filename == NULL) {
            fprintf(stderr, "Error: value in paths array is not a string\n");
            return false;
        }

        tpm_hash_t digest;
        if (!pe_image_measure1(filename, &digest)) {
            fprintf(stderr, "Error: Could not calculate PE32+ image hash: %s\n", filename);
            return false;
        }

#if SEALKEY_DEBUG_OUT
		print_hex((uint8_t*) &digest, TPM12_HASH_LEN);
		printf(" %s\n", filename);
#endif

        TPM12_Chain_Update(&chain_ctx, &digest);
    }

    TPM12_Chain_Finalize(&chain_ctx, chained_digest);

    return true;
}

/**
 * Read boot options from a systemd-boot configuration file and calculate PCR 8
 */
static inline bool calculate_boot_options(const char* path, tpm_hash_t* chained_digest) {
    assert(path);
    assert(chained_digest);

    tpm_hash_t md;
    TPM12_Chain_Context ctx;
    TPM12_Chain_Init(&ctx);

    if (!kernel_params_measure1(path, &md)) {
        fprintf(stderr, "Error: Could not calculate boot options hash: %s\n", path);
        return false;
    }

    TPM12_Chain_Update(&ctx, &md);
    TPM12_Chain_Finalize(&ctx, chained_digest);
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
 */
static bool calculate_pcrs_object(json_object_t sub_conf, int pcr, pcr_ctx_t* ctx) {
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

        if (!calculate_load_image_array(array, &ctx->pcrs[pcr])) {
            return false;
        }
    } else if (strcmp("systemd-boot-entry", type) == 0) {
        json_object_t path;
        if(!json_object_object_get_ex(sub_conf, "path", &path)) {
            fprintf(stderr, "Error: path missing from systemd-boot-entry type\n");
            return false;
        }

        if (json_object_get_type(path) != json_type_string) {
            fprintf(stderr, "Error: paths in systemd-boot-entry type, is not a string\n");
            return false;
        }

        const char* file = json_object_get_string(path);
        if (!calculate_boot_options(file, &ctx->pcrs[pcr])) {
            return false;
        }
    } else if (strcmp("pcr", type) == 0) {
        // marked as selected in caller
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
            struct json_object* pcr_val = json_object_iter_peek_value(&iter);
            int pcr = strtol(name, NULL, 10);
            if (pcr < 0 || pcr >= PCR_LENGTH) {
                fprintf(stderr, "Error: Invalid PCR[%02d] for lock selected\n", pcr);
                return false;
            }

            enum json_type type = json_object_get_type(pcr_val);
            switch (type) {
                case json_type_string:
                    if (strcmp("pcr", json_object_get_string(pcr_val)) == 0) {
                        add_pcr_to_composite(pcr, selected_pcrs);
                    } else {
                        fprintf(stderr, "Error: Invalid configuration value for PCR[%02d]: %s\n", pcr, json_object_get_string(pcr_val));
                        return false;
                    }
                    break;
                case json_type_object:
                    if (calculate_pcrs_object(pcr_val, pcr, ctx)) {
                        add_pcr_to_composite(pcr, selected_pcrs);
                    } else {
                        return false;
                    }
                    break;
                default:
                    fprintf(stderr, "Error: Invalid JSON type for PCR[%02d]: %s\n", pcr, json_type_to_name(type));
                    return false;
                    break;
            }
        }
    }
    return true;
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
        print_hex(pcr_ctx.pcrs[i].digest, TPM12_HASH_LEN);
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
#if SEALKEY_DEBUG_OUT
    // printf("%s\n", pcrinfo);
    //4  a32905cb0605b84c3651708d80837779fca0484d
    //8  940e2c77b9d3301be61dcf1ce1c05859ef76daed
    //000210016dd4ce2f5ea9a67953cd3717dd31fa9e3daf59740000000000000000000000000000000000000000
#endif
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
	fprintf(stderr, "keyctl add trusted %s \"%s\" @u\n", key_name, parameters);
#endif
	key_num = add_key("trusted", "kmk", parameters, strlen(parameters), KEY_SPEC_USER_KEYRING);
	
	if (key_num == -1) {
        if (errno == ENODEV) {
            fprintf(stderr, "Error: Check if the kernel module `trusted´ is loaded.\n");
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
	fprintf(stderr, "keyctl update %d \"%s\" @u\n", key_id, parameters);
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
            print_hex((uint8_t*) &pcr_ctx.pcrs[i], TPM12_HASH_LEN);
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
            print_hex((uint8_t*) &pcr_ctx.pcrs[i], TPM12_HASH_LEN);
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

static void print_usage() {
    printf(PROGRAM_NAME " " PROGRAM_VERSION"\n");
    printf("\n");
    printf(PROGRAM_NAME " new <configfile> [<outfile>]\n");
    printf("   Create a new key with specified configuration\n");
    printf("\n");
    printf(PROGRAM_NAME " update <configfile> [<outfile>]\n");
    printf("   Update an exisiting key with specified configuration\n");
    printf("\n");
#if USE_TSPI
    printf(PROGRAM_NAME " tpm_seal <configfile> [<inputfile>] [<outfile>]\n");
    printf("   Seal a new file with PCR configuration\n");
    printf("\n");
    printf(PROGRAM_NAME " tpm_update <configfile> <inputfile> [<outfile>]\n");
    printf("   Update the seal on an exisiting encrypted file with PCR configuration\n");
    printf("\n");
#endif // USE_TSPI
    printf(PROGRAM_NAME " pcrinfo <configfile> [<outfile>]\n");
    printf("   Just generate the PCR_INFO struct, suitable for calling keyctl\n");
    printf("\n");
    printf(PROGRAM_NAME " pcr current <configfile>\n");
    printf("   Show selected PCRs from the System's Firmware (read from /sys/class/tpm/tpm0)\n");
    printf("\n");
    printf(PROGRAM_NAME " pcr updated <configfile>\n");
    printf("   Show selected the PCRs according to configfile\n");
    printf("\n");
    printf("Configuration file JSON format:\n");
    printf("  {\n");
    printf("    \"key\": { \"name\": \"kmk\", \"size\": 32 },\n");
    printf("    \"pcrlock\": {\n");
    printf("      \"0\": { \"type\": \"pcr\" },\n");
    printf("      \"4\": { \"type\": \"load-image\", \"paths\": [ \"/boot/EFI/BOOT/BOOTX64.EFI\", \"/boot/vmlinuz-linux\" ] },\n");
    printf("      \"8\": { \"type\": \"systemd-boot-entry\", \"path\": \"/boot/loader/entries/linux.conf\" }\n");
    printf("    }\n");
    printf("  }\n");
    printf("\n");
    printf("The \"key\" section describes key name and length for newly created keys and key updates\n");
    printf("  Keys are created in kernel, the kernel module trusted.ko must be loaded. Keys can be\n");
    printf("  inspected using the keyctl utility.\n");
    printf("The \"pcrlock\" section lists PCRs for sealing the key, the following types are recognized:\n");
    printf("  \"pcr\" read the PCR from the Firmware and use it for sealing\n");
    printf("  \"load-image\" create PCR 4 hash from the list in \"paths\"\n");
    printf("  \"systemd-boot-entry\" create hash the same way systemd-boot creates PCR 8 from kernel parameters\n");
}

#if SEALKEY_DEBUG_OUT
static void* crypto_mem_leak_cb(unsigned long order, const char *file, int line, int num_bytes, void *addr) { 
    fprintf(stderr, "Leak: Order: %7lu, File: %-28s, Line: %4d, Bytes: %5d, Addr: %p\n", order, file, line, num_bytes, addr); 
    return addr; 
}
#endif

int main(int argc, char* argv[]) {
    int ret = 1;

    if (argc > 2) {
        if (strcmp(argv[1], "pcr") == 0 && argc > 3) {
            json_object_t configuration = NULL;
            if (!configfile_read(argv[3], &configuration))
                return 1;
            
            if (json_object_get_type(configuration) != json_type_object) {
                fprintf(stderr, "Error: Configuration is not a JSON object\n");
                configfile_free(configuration);
                return 1;
            }

            if (strcmp(argv[2], "current") == 0) {
                if (pcr_current_command(configuration))
                    ret = 0;
            } else if (strcmp(argv[2], "updated") == 0) {
                if (pcr_updated_command(configuration))
                    ret = 0;
            } else {
                print_usage();
                goto cleanup;
            }

            configfile_free(configuration);
        } else {
            json_object_t configuration = NULL;
            if (!configfile_read(argv[2], &configuration))
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
                    print_usage();
                    goto cleanup;
                }

                if (new_command(configuration, outfile))
                    ret = 0;
            } else if (strcmp(argv[1], "update") == 0) {
                if (argc == 4) {
                    outfile = argv[3];
                } else if (argc == 3) {
                } else {
                    print_usage();
                    goto cleanup;
                }

                if (update_command(configuration, outfile))
                    ret = 0;
            } else if (strcmp(argv[1], "pcrinfo") == 0) {
                if (argc == 4) {
                    outfile = argv[3];
                } else if (argc == 3) {
                } else {
                    print_usage();
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
                    print_usage();
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
                    print_usage();
                    goto cleanup;
                }

                if (tpm_update_command(configuration, infile, outfile))
                    ret = 0;
#endif // USE_TSPI
            } else {
                print_usage();
                goto cleanup;
            }

    cleanup:
            CRYPTO_cleanup_all_ex_data();
            configfile_free(configuration);
    	}
    } else {
		print_usage();
	}

#if SEALKEY_DEBUG_OUT
    CRYPTO_mem_leaks_cb(crypto_mem_leak_cb); 
#endif
	
	return ret;
}
