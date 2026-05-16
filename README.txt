# UNFAIR

Unfair decrypts FairPlay-protected Mach-O binaries in IPA packages.

Licensed under MIT.

Run `./unfair --help` for command details.

## macOS

macOS support requires Apple Silicon on macOS 11.2.3 or earlier.

Build:

```sh
make
```

Install:

```sh
make install
```

The default prefix is `/usr/local`. Use `PREFIX=/path` to install elsewhere.
If `/usr/local` is not writable, run `sudo make install`.

## iOS

iOS support is for jailbroken devices where the target app must be installed
under `/var/containers/Bundle/Application` before decryption.

Requirements:

- SSH access as `root`
- `/var/jb/usr/bin/appinst`
- `/var/jb/usr/bin/ldid`
- `/var/jb/usr/lib/libjailbreak.dylib` or `/var/jb/basebin/libjailbreak.dylib`

Build and send the binary to the device:

```sh
./build-iOS.sh ip
```

The script builds an arm64 iOS binary, signs it with `global.xml`, copies
`unfair` and `global.xml` to the device, and signs the remote binary again with
the device-side `ldid`.

Copy the IPA to the device:

```sh
scp Example.ipa root@ip:/var/tmp/Example.ipa
```

Decrypt the IPA on the device:

```sh
ssh root@ip '~/unfair package \
  -i /var/tmp/Example.ipa \
  -o /var/tmp/Example.unfair.ipa \
  -v'
```

Copy the result back:

```sh
scp root@ip:/var/tmp/Example.unfair.ipa ./Example.unfair.ipa
```

The iOS package flow installs the IPA with `appinst`, locates the installed
`.app` bundle under `/var/containers/Bundle/Application`, prepares decryption
permissions through jailbreak primitives, maps encrypted regions with
`PROT_READ | PROT_EXEC`, writes decrypted bytes back in place, then removes the
installed app container.

The output IPA omits `Payload/*.app/SC_Info/**` because those FairPlay support
files can contain user-specific account data. The installed app copy still uses
`SC_Info` during decryption.

Verify the output:

```sh
unzip -t Example.unfair.ipa
unzip -l Example.unfair.ipa | grep SC_Info
rm -rf /tmp/unfair-verify
mkdir -p /tmp/unfair-verify
unzip -q Example.unfair.ipa -d /tmp/unfair-verify
otool -l /tmp/unfair-verify/Payload/Example.app/Example | grep -A5 LC_ENCRYPTION_INFO_64
```

The `SC_Info` check should print no entries. The expected encrypted Mach-O
state is `cryptid 0`.
