---
title: Approving and Revoking Certificates
type: how-to
description: As an officer of a CA, find held requests, approve or deny
  them, and revoke certificates that are not to be trusted.
related:
  - peios/certificate-authority/overview
  - peios/certificate-authority/publishing-revocation-lists
  - peios/certificate-authority/requesting-a-certificate
  - peios/certificate-authority/controlling-who-can-request-certificates
---

Approve and revoke certificates when a CA holds requests for an officer, or
when a certificate's key is lost or its holder leaves. These are an
officer's tasks: they need the Officer right in the CA's descriptor, which
Administrators hold by default.

## Before you start

- Sign in as an officer of the CA.

## Approve or deny held requests

1. List the requests waiting for an officer:

   ```sh
   pki request list "Home Issuing" --status pending
   ```

   Each is listed with its number, template, when it was submitted, and the
   names it asks for.

2. Look at a request in full, including who submitted it and why it was
   held:

   ```sh
   pki request show "Home Issuing" 42
   ```

3. Approve it, which issues the certificate:

   ```sh
   pki request approve "Home Issuing" 42
   ```

   Or deny it, recording why:

   ```sh
   pki request deny "Home Issuing" 42 --reason "not a lab machine"
   ```

You can't approve a request you submitted yourself; another officer has to.
pkid checks an approved request again as its requester, so approving it
issues only what the requester was allowed to ask for, whatever the
officer's own rights.

The requester then collects the certificate, as described in
[Requesting a Certificate](~peios/certificate-authority/requesting-a-certificate).

## Revoke a certificate

1. Find the certificate's serial number:

   ```sh
   pki cert list "Home Issuing"
   ```

2. Revoke it, with the reason, such as `key-compromise` for a key that was
   exposed or `superseded` for one that was replaced:

   ```sh
   pki cert revoke "Home Issuing" 4f1a09 --reason key-compromise
   ```

A revocation can't be undone. pkid records it with its reason, the time, and
the officer who made it. `pki(8)` lists every reason.

Software learns of the revocation from the CA's revocation list. pkid
publishes a new list at once for a CA whose key it keeps. For a CA whose key
is in a sealed file, `pki` reminds you to publish one with
`pki ca publish-crl`, as described in
[Publishing Revocation Lists](~peios/certificate-authority/publishing-revocation-lists).

## Check the result

Show the certificate:

```sh
pki cert show "Home Issuing" 4f1a09
```

Its state is `revoked`, with when, why, and by whom. A request you approved
or denied leaves the list that `pki request list "Home Issuing" --status
pending` prints.
