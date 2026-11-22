---
title: Publishing Revocation Lists
type: how-to
description: Give each CA a CRL address, serve its revocation lists over HTTP
  with pki-httpd, and keep an offline root's list from expiring.
related:
  - peios/certificate-authority/overview
  - peios/certificate-authority/approving-and-revoking-certificates
  - peios/certificate-authority/setting-up-a-certificate-authority
---

Publish revocation lists so that software checking a certificate can find
out whether it was revoked. Each CA signs a certificate revocation list
(CRL) naming the certificates it has revoked, and pki-httpd serves it over
HTTP at the address the CA writes into every certificate it issues.

A revocation has no effect on software that never fetches the list, and
software that does fetch it rejects every certificate below a CA whose list
has expired. So a CA needs both an address that will keep working and a list
that is kept current.

## Before you start

- Sign in as a member of Administrators.
- Choose a host name for the address that will outlive this machine, such as
  `pki.home`, and make it resolve to this machine. The address is written
  into each certificate when it is issued, so changing it later leaves every
  certificate already issued pointing at the old one.
- Make sure the pkid and pki-httpd services are installed, and run
  `pki setup`, which reserves TCP port 80 for pki-httpd.

## Give each CA an address

1. Give a CA its address when you create it, with `--crl`:

   ```sh
   pki ca create "Home Root" --root --key-file /media/usb/home-root.key \
     --crl http://pki.home/crl/home-root.crl
   pki ca create "Home Issuing" --issuer "Home Root" \
     --template Server --template Device \
     --crl http://pki.home/crl/home-issuing.crl
   ```

   The root's address goes into the certificates the root signs, so the
   issuing CA's certificate carries it, and the issuing CA's address goes
   into the certificates it issues.

2. For a CA that exists already, set its address with `ca set`. Only
   certificates issued afterward carry it:

   ```sh
   pki ca set "Home Issuing" --crl http://pki.home/crl/home-issuing.crl
   ```

pki-httpd serves each list at the path of its address, so
`http://pki.home/crl/home-issuing.crl` is served as `/crl/home-issuing.crl`.
Use letters, digits, `.`, `-`, `_`, and `~` in each part of the path.

## Keep each list current

A CA whose key pkid keeps, such as the issuing CA, looks after its own list:
pkid signs a new one after every revocation and at half each list's
lifetime, which is 7 days unless you change it.

A CA whose key is in a sealed file, such as an offline root, can sign only
with its passphrase, so you renew its list by hand. Its lists last 180 days.

1. Mount the media holding the root's key.
2. Sign and publish a new list:

   ```sh
   pki ca publish-crl "Home Root"
   ```

   `pki` asks for the root key's passphrase.

Do this after the root revokes anything, and well before its list expires:
`pki ca list` flags a list that expires within 30 days, and pkid emits a
`pkid.crl.expiring` event each day until it is renewed.

To change how long a CA's lists last:

```sh
pki ca set "Home Root" --crl-lifetime 365
```

In the Certificate Authority window, a CA's page shows its latest list and
when it expires, and **Publish Now** signs a new one, asking for the key's
passphrase if it is sealed. The overview lists each list that is due or has
expired.

## Check the result

List the CAs and when their lists expire:

```sh
pki ca list
```

Then fetch a list from another machine, such as with `curl`, and check it
names the CA:

```sh
curl -o home-issuing.crl http://pki.home/crl/home-issuing.crl
openssl crl -inform DER -in home-issuing.crl -noout -issuer -nextupdate
```

## Serve on another port

If another service already serves port 80, `pki setup` warns that the port
is reserved for it. Choose another port for pki-httpd, such as 8080, by
setting `Machine\Software\Pki\Http Port`, and run `pki setup` again to
reserve it. Restart pki-httpd, and give each CA an address with that port,
such as `http://pki.home:8080/crl/home-issuing.crl`. `pki-httpd(8)` describes
the service.
