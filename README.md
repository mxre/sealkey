sealkey
=======

Sealkey is a tool that allows to seal data and Linux kernel keys (using the `trusted` kernel module)
and protect them using a Trusted Platform Module (TPM). Currently only TPM 1.2 is supported.

In contrast to the command `tpm_sealdata` supplied by [tpm_tools][1], sealkey allows to specifiy how the
PCRs (Platform configuration registers) are calculated, thus allowing to seal data with new PCR values
after a kernel update and before a reboot.

Supported Systems
-----------------

I developed and tested sealkey successfully only on a Laptop with a TPM 1.2 running in UEFI mode.

Currently the following libraries are neccesary to build sealkey:
 - keyutils
 - openssl
 - json-c

Configuration
-------------

sealkey reads the setting, on how to generate the PCRs for sealing from a JSON file.

~~~~~~~~~~~~~{.js}
{
  "key": { "name": "kmk", "size": 32 },
  "pcrlock": {
    "0": { "type": "pcr" },
    "1": { "type": "pcr" },
    "2": { "type": "pcr" },
    "3": { "type": "pcr" },
    "4": { "type": "load-image", "paths": [ "/boot/EFI/BOOT/BOOTX64.EFI", "/boot/vmlinuz-linux" ] },
    "5": { "type": "pcr" },
    "8": { "type": "systemd-boot-entry", "path": "/boot/loader/entries/arch.conf" }
  }
}
~~~~~~~~~~~~~

 - The *key* section describes key name and length for newly created keys and key updates
   Keys are created in kernel, the kernel module `trusted.ko` must be loaded. Keys can be
   inspected using the `keyctl` utility.
 - The *pcrlock* section lists PCRs for sealing the key, the following types are recognized:
   - *pcr* read the PCR from the Firmware and use it for sealing
   - *load-image* create a PCR 4 hash from the list in *paths*, this should result in the same hash
     that is created by the UEFI `LoadImage()` function, *paths* should have a list of UEFI applications
     in the order they are called eg, first the Bootloader then the Kernel.
   - *systemd-boot-entry* create hash the same way systemd-boot creates PCR 8 from kernel parameters.
     If `systemd` is build with the `--enable-tpm` configure option, systemd-boot supports measuring
     the supplied kernel commandline, to a PCR specified at compile time. The default is PCR 8.

Optional TCSD
-------------

Support for TCSD (Trousers Daemon) is optinal an can be switched of in the Makefile cf, `-DUSE_TSPI=1` C Flag.
TCSD support additionally needs to heave tpm_tools installed, specfically, the `libtpm_unseal.so` library.

[1]: https://sourceforge.net/projects/trousers/
