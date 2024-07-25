# talos-unlockr

This is more or less the same functionality as [the reference KMS repo](https://github.com/siderolabs/kms-client), except in Rust.

`talos-unlockr` takes either:

- a 256-bit key
  - create one using something like `argon2 mysalt -id -r | xxd -r -p - talos.key`
- a passphrase and runs Argon2 as KDF with node UUIDs salt

and uses chacha20poly1305 to seal and unseal data for
[Talos disk encryption](https://www.talos.dev/v1.7/talos-guides/configuration/disk-encryption/).

Additional options:

- specific IPs to restrict the source of requests
- timeout to exit after

## Running as a service

The unlocker can be run as a systemd service.

For example, generate a key from a password and put it in `credstore.encrypted`:

```
argon2 mysalt -id -r \
  | xxd -r -p - - \
  | sudo systemd-creds encrypt - /etc/credstore.encrypted/talos.key --name talos.key
```

```
[Unit]
Description=Unlock encrypted Talos
Wants=network-online.target
After=network-online.target

[Service]
ConfigurationDirectory=talos-unlockr
EnvironmentFile=%E/talos-unlockr/flags.env
LoadCredentialEncrypted=talos.key:talos.key
ExecSearchPath=/usr/local/bin
ExecStart=talos-unlockr --key-file %d/talos.key $FLAGS
Restart=on-failure
Type=exec

[Install]
WantedBy=multi-user.target
```
