---
title: Requesting a Certificate
type: how-to
description: "Have a CA certify a request you made, or make a key and a
  certificate for a device in one PKCS #12 file, and collect a certificate
  that waited for approval."
related:
  - peios/certificate-authority/overview
  - peios/certificate-authority/controlling-who-can-request-certificates
  - peios/certificate-authority/approving-and-revoking-certificates
---

Request a certificate when a server, a service, or a device needs one from
your CA. You can send a request that other software made, or have `pki`
make the key and package the result for a device to import.

## Before you start

- Find the CA's name and the template to use. `pki ca list` lists the CAs
  you have rights at, and `pki ca show` lists the templates a CA issues
  from.
- Make sure you can request the names the certificate is to carry, as
  described in
  [Controlling Who Can Request Certificates](~peios/certificate-authority/controlling-who-can-request-certificates).

## Certify a request you made

Software that keeps its own key, such as a web server, makes the request
itself, in PEM or DER. Submit it under a template the CA offers:

```sh
pki request submit "Home Issuing" Server www.csr --out www.pem
```

If the CA issues the certificate, `pki` writes it to `www.pem`. If the
request is held for approval, `pki` prints its number instead. Once an
officer approves it, collect the certificate:

```sh
pki cert get "Home Issuing" 42 --out www.pem
```

## Make a key and certificate for a device

Phones, laptops, and other devices import a key and its certificates as one
PKCS #12 file. `pki enroll` makes the key on this machine, asks the CA to
certify it, and writes the file:

```sh
pki enroll "Home Issuing" Device --upn alice@home --out alice.p12
```

`pki` asks for a passphrase of at least 15 characters, which protects the
file and is asked for again when it is imported. pkid sees only the request,
never the key. The file holds the key, the certificate, and the CA
certificates above it that you can see on this pkid, so a device that
imports it can present the chain.

Name the certificate with `--dns` for a host name, `--email` for an email
address, or `--upn` for a user principal name, which EAP-TLS sign-in to
Wi-Fi uses. Each can be repeated.

The file is encrypted with AES-256, as OpenSSL 3 writes by default, and
OpenSSL 3 imports it. Apple systems older than iOS 18 and macOS 15 are
reported to refuse it.

### When the request is held

The key exists nowhere but on this machine, so a held request can't lose
it: `pki` seals the key under the same passphrase in a file beside the one it
would have written, here `alice.p12.key`, and prints the command that
finishes the job. Once an officer approves request 42, run:

```sh
pki enroll "Home Issuing" --request 42 --key alice.p12.key --out alice.p12
```

Delete `alice.p12.key` once the device has imported the file.

## Check the result

List the CA's certificates:

```sh
pki cert list "Home Issuing"
```

The new certificate is listed with the state `valid`, its serial number,
and when it expires. `pki cert show` with the serial number shows it in
full.
