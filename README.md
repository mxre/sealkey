sealkey
=======

Sealkey is a tool that allows to seal data and Linux kernel keys (using the `trusted` kernel module)
and protect them using a Trusted Platform Module (TPM). Currently only TPM 1.2 is supported.

In contrast to the command `tpm_sealdata` supplied by [tpm_tools][1], sealkey allows to specifiy how the
PCRs (Platform configuration registers) are calculated, thus allowing to seal data with new PCR values
after a kernel update and before a reboot.

Supported Systems
-----------------

I developed and tested sealkey successfully on a Laptop with a TPM version 1.2 running in UEFI mode.

Currently the following libraries are neccesary to build sealkey:
 - keyutils
 - openssl
   `libcrypto` with AES-CBC, RSA and SHA1 support is needed. Other implementations like libressl might work too.
 - json-c
 - libefivar

Configuration
-------------

sealkey reads the setting, on how to generate the PCRs for sealing from a JSON file.

~~~~~~~~~~~~~{.js}
{
  "key": { "name": "kmk", "size": 32 },
   "bootloader": {
     "type" : "systemd-boot",
     "esp"  : "/boot",
     "entry": "linux"
  },
  "pcrlock": {
    "0": { "type": "pcr" },
    "1": { "type": "pcr" },
    "2": { "type": "pcr" },
    "3": { "type": "pcr" },
    "4": { "type": "load-image", "paths": [ "$efiboot:default", "$linux" ] },
    "5": { "type": "pcr" },
    "8": { "type": "entry-cmdline" }
  }
}
~~~~~~~~~~~~~

 - The *key* section describes key name and length for newly created keys and key updates
   Keys are created in kernel, the kernel module `trusted.ko` must be loaded. Keys can be
   inspected using the `keyctl` utility.
 - The *bootloader* section contains information on the configuration of the bootloader.
   Currently only *systemd-boot* is supported. The key *entry* is mandatory, it is used
   to read the used kernel image, initrd and kernel commandline.
 - The *pcrlock* section lists PCRs for sealing the key, the following types are recognized:
   - *pcr* read the PCR from the Firmware and use it for sealing, this type supports the optional
     key *value* that allows to set a SHA-1 hash directly in the configuration file.
   - *load-image* create a PCR 4 hash from the list in *paths*, this should result in the same
     hash that is created by the UEFI `LoadImage()` function, *paths* should have a list of
     UEFI applications in the order they are called eg, first the Bootloader then the Kernel.
     The paths are relative the the ESP. There are also special value, that automatically
     retrieve the paths:
     - `$efiboot:default` and `$efiboot:current` read the first bootloader or current bootloader
        from the EFI variables. Be careful when using `$efiboot:default` the first loader
        in the BootOrder list is used, if it isn't an EFI executable e.g., a disk entry, it won't work.
     - `$efiboot:XXXX` use the entry with the specified number, see output of `efimootmgr`.
     - `$linux` for the linux kernel provided by the bootloader entry.
   - *entry-cmdline* create a hash the same way systemd-boot creates PCR 8 from kernel parameters.
     If `systemd` is built with the `--enable-tpm` configure option, systemd-boot supports measuring
     the supplied kernel commandline, to a PCR specified at compile time. The default is PCR 8.

`json-c`, the JSON parser, uses sloppy rules, so several extensions to JSON files are working i.e.,
JavaScript comments.

Optional TCSD
-------------

Support for TCSD (Trousers Daemon) is optional an can be switched off in the Makefile cf, `-DUSE_TSPI=1` C Flag.
TCSD support additionally needs to heave tpm_tools installed, specfically, the `libtpm_unseal.so` library.

[1]: https://sourceforge.net/projects/trousers/
