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

create a service file `/etc/systemd/system/talos-unlockr.service`:

```
[Unit]
Description=Unlock encrypted Talos
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
ConfigurationDirectory=talos-unlockr
EnvironmentFile=%E/talos-unlockr/flags.env
LoadCredentialEncrypted=node.key:node.k8rn.talos.key
LoadCredentialEncrypted=key.pem:talos-unlockr.key.pem
LoadCredentialEncrypted=crt.pem:talos-unlockr.crt.pem
ExecSearchPath=/usr/local/bin
ExecStart=talos-unlockr --key-file %d/node.key --tls-key %d/key.pem --tls-cert %d/crt.pem $FLAGS
Restart=on-failure
ProtectHome=yes
PrivateUsers=yes
DynamicUser=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
CapabilityBoundingSet=
ProtectControlGroups=strict
ProtectSystem=strict
ProtectProc=invisible
ProtectHostname=yes
PrivateNetwork=yes
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=none
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @privileged @raw-io @reboot @resources @swap
IPAddressDeny=any
UMask=0077

[Install]
WantedBy=multi-user.target
```

and a socket file `/etc/systemd/system/talos-unlockr.socket`:

```
[Unit]
Description=GRPC socket for talos-unlockr

[Socket]
ListenStream=11111
BindIPv6Only=both
Accept=no
FileDescriptorName=grpc
Service=talos-unlockr.service
IPAddressAllow=192.168.0.0/24
IPAddressDeny=any

[Install]
WantedBy=sockets.target
```

## Telegram bot

`talos-unlockr` can also be run alongside a Telegram bot. The bot can be used to
notify about and allow attempts to seal/unseal.

```
[Unit]
Description=Telegram bot for talos-unlockr
Wants=network-online.target
After=network-online.target
JoinsNamespaceOf=talos-unlockr.service

[Service]
Type=exec
ExecStart=telegram-bot --socket /tmp/talos-unlockr.sock --user-id <TELEGRAM_USER> --allowed-ips <CLUSTER_NAME>/<IP>/<UUID>
Environment=TELOXIDE_TOKEN=...
Restart=on-failure
PrivateMounts=yes
PrivateTmp=yes
DynamicUser=yes
# ... other security options

[Install]
WantedBy=multi-user.target
```

and add to `talos-unlockr.service`:

```
[Unit]
Wants=talos-unlockr-bot.service

[Service]
ExecStart=... --socket /tmp/talos-unlockr.sock
PrivateTmp=yes
```
