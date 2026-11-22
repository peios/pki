---
title: Setting Up a Certificate Authority
type: how-to
description: Prepare a Peios machine for pkid, create a root CA with its key
  on removable media and an issuing CA below it, and distribute the root.
related:
  - peios/certificate-authority/overview
  - peios/certificate-authority/publishing-revocation-lists
  - peios/certificate-authority/controlling-who-can-request-certificates
  - peios/certificate-trust/adding-and-distrusting
---

Set up a certificate authority when the machines and people on your network
need certificates you issue yourself. When you finish, you have a root CA
whose key is kept off the machine and an issuing CA that issues server and
device certificates unattended.

## Before you start

- Sign in as a member of Administrators.
- Make sure the `pki` package is installed. It doesn't start pkid or
  pki-httpd: they start once you set the machine up.
- Have removable media mounted for the root's key, such as `/media/usb`.
- Choose a passphrase of at least 15 characters for the root's key, and
  somewhere safe to keep it. Without the passphrase, the root can never sign
  again.

## Prepare the machine

Run `pki setup` once:

```sh
pki setup
```

It creates pkid's state directories under `/var/state/pki` and adds the
default configuration under `Machine\Software\Pki`: the Server and Device
templates and the roots of the name trees. Then it has pkid, and pki-httpd,
which publishes revocation lists, start at boot, and starts them. It only
adds what is missing, so running it again changes nothing you have set.

In the Certificate Authority window, the overview offers **Set Up** to an
administrator until the machine is prepared.

## Create the root

1. Create the root, with its key sealed in a file on the removable media:

   ```sh
   pki ca create "Home Root" --root --key-file /media/usb/home-root.key \
     --crl http://pki.home/crl/home-root.crl
   ```

   `pki` asks for the key's passphrase twice. pkid makes the key and the
   root's certificate, an RSA-4096 one that lasts 10 years. `--crl` is the
   address where the root's revocation list will be published, and goes
   into the certificates the root signs; see
   [Publishing Revocation Lists](~peios/certificate-authority/publishing-revocation-lists).

2. Publish the root's first revocation list while its key is to hand:

   ```sh
   pki ca publish-crl "Home Root"
   ```

3. Write the root's certificate to a file, to give to the devices that are
   to trust it:

   ```sh
   pki ca show "Home Root" --out home-root.pem
   ```

## Create the issuing CA

1. Create the issuing CA, signed by the root, issuing from both templates:

   ```sh
   pki ca create "Home Issuing" --issuer "Home Root" \
     --template Server --template Device \
     --crl http://pki.home/crl/home-issuing.crl
   ```

   `pki` asks for the root key's passphrase, since the root signs the new
   CA's certificate. The issuing CA's key goes in pkid's store, so it issues
   without a passphrase, and its certificate lasts 5 years. pkid publishes
   its revocation lists itself.

2. Unmount the removable media and store it safely. The root is needed again
   to sign another CA, and to renew its revocation list, which lasts 180
   days.

## Check the result

List the CAs:

```sh
pki ca list
```

Both CAs are listed, each with the state `issuing`. `pki ca show
"Home Issuing"` shows the issuing CA in full, including the templates it
issues from and its certificate's SHA-256 fingerprint.

## Distribute the root

Every device that is to trust your certificates needs `home-root.pem` in its
trust store. Check its SHA-256 fingerprint against `pki ca show "Home Root"`
when you install it. On a Peios machine, add it as described in
[Adding and Distrusting Certificates](~peios/certificate-trust/adding-and-distrusting).

## Keep a copy of the issuing CA's key

A key in pkid's store can't leave it unless the CA was created with
`--exportable`. To be able to restore the issuing CA on another machine, add
`--exportable` when you create it, then export its key, sealed under a new
passphrase:

```sh
pki ca export-key "Home Issuing" home-issuing.key
```

`pki ca import` restores it from the file and the CA's certificate.

## Have a CA elsewhere sign your CA

If your network already has a CA, make pkid's CA its subordinate instead of
a root. `--offline` writes a request for that CA to sign:

```sh
pki ca create "Home Issuing" --offline home-issuing.csr
```

Once the other CA has signed it, install the certificate it returns:

```sh
pki ca install "Home Issuing" home-issuing.pem
```

The CA issues nothing until its certificate is installed.

## Use the Certificate Authority window

**Add an Authority** in the window's sidebar makes each kind of CA these
steps make: a **Root Authority**, one **Under an Authority Here**, one
**Signed by an Authority Elsewhere**, or one imported from a backup with
**Import From a Backup**. Its **Key Storage** is the Certificate Service's
store, or a **Sealed File** with a passphrase. A CA's page has **Export
Key**, **Sign a Subordinate Request**, and, while it waits for its
certificate, **Save Request…** and **Install Certificate…**. Only someone
with the right to create CAs sees **Add an Authority**.
