# mist-enroll

Enrolls a Linux machine with Juniper Mist NAC over SCEP and writes ready-to-use
NetworkManager 802.1X (EAP-TLS) profiles for **wireless** and **wired**.

## Requirements

Python 3 and `openssl`.

## Getting an enrollment URL

1. Go to <https://eduroam.plymouth.ac.uk>
2. Sign in, then click **Install network profile**
3. Copy the entire `marvisclient://api.eu.mist.com/...` link

If the link doesn't appear, try another browser such as Chromium — Firefox did not work for me.

## Usage

```sh
./mist-enroll
```

It writes two files into the current directory and prints the commands to
install them. It does not modify the system itself.

- `plymouth_eduroam.nmconnection` — wireless (SSID `eduroam`)
- `plymouth_wired.nmconnection` — wired

Then:

```sh
sudo install -o root -g root -m 600 plymouth_eduroam.nmconnection /etc/NetworkManager/system-connections/
sudo install -o root -g root -m 600 plymouth_wired.nmconnection /etc/NetworkManager/system-connections/
sudo nmcli connection reload
shred -u plymouth_eduroam.nmconnection plymouth_wired.nmconnection
```

## ⚠️ These files contain your private key

Both profiles embed the client certificate, private key and CA certificate
inline. Anyone with a copy can join the network as you. Don't email them, share
them, or commit them — and `shred` the local copies once installed.

## What it does

Posts a random device ID to the enrollment URL to get your 802.1X identity, the
SCEP URL and a one-time challenge; generates an RSA key and CSR; runs a SCEP
`PKCSReq` against the Mist CA to get a certificate issued; then writes the two
profiles with the key and certificate embedded.

All cryptography is done by `openssl`. The SCEP `pkiMessage` is assembled by
hand because it needs CMS authenticated attributes, which `openssl` cannot do by itself.

## Tests

```sh
python3 tests/run.py
```

Runs against a mock SCEP CA backed by a real openssl CA; `openssl` is required
for the tests as well.
