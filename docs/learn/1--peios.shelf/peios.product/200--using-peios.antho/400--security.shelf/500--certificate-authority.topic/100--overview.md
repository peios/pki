---
title: The Certificate Authority
type: concept
description: How pkid issues certificates for a Peios machine's network, and
  how CAs, templates, names, and requests decide what it issues and to whom.
related:
  - peios/certificate-authority/setting-up-a-certificate-authority
  - peios/certificate-authority/controlling-who-can-request-certificates
  - peios/certificate-authority/requesting-a-certificate
  - peios/certificate-trust/overview
---

A Peios machine can run its own certificate authority: pkid, a service that
issues X.509 certificates for the machines, services, and people on your
network, such as a server's TLS certificate or the certificate a phone signs
in to Wi-Fi with. If you have run an enterprise certificate authority, the
pieces will be familiar: CAs, templates that describe each kind of
certificate, and requests that are issued at once or held for an officer.

You manage pkid with the `pki` command. pkid decides every request by the
access token of whoever sent it, so `pki` can do exactly what you can, and
nothing more.

## How a certificate is issued

A certificate starts as a request: a public key and the names it is for,
signed with the matching private key to prove the requester holds it. The
request names a CA and a template, and pkid checks it in this order:

1. **The CA.** The requester needs the Request right in the CA's security
   descriptor.
2. **The template.** The requester needs the Enroll right in the template's
   descriptor, and the request has to fit the template: the kinds of key and
   name it allows.
3. **Each name.** The requester needs the right to request every name in the
   certificate, from the name trees.

A request that passes is issued at once, or held for an officer of the CA to
approve, when the template or a name asks for approval. A request that fails
any check is refused, with the reasons. pkid records every request and
decision in its database, with who made it.

The template decides everything else about the certificate: its purposes,
key usages, and lifetime. A requester can't change any of it, so the
template, not the request, is what an administrator reviews.

## CAs

A CA is a key and a certificate that signs other certificates. Most networks
have two tiers:

- A **root** signs its own certificate. Every device that is to trust your
  certificates adds the root's certificate to its trust store once.
- An **issuing CA** below the root signs the certificates people and
  machines use. Its certificate is signed by the root.

Two tiers let you keep the root's key away from the network. pkid keeps a
CA's key in one of two places:

- **pkid's store**, readable by pkid's service account alone. A CA whose key
  is here issues unattended, as an issuing CA does.
- **A sealed file**, protected by a passphrase, such as on removable media.
  pkid never keeps such a key open: every operation that signs with it asks
  for the passphrase. A root's key belongs here, and the media can stay in a
  drawer until the root next signs something.

A CA can also be signed by a CA elsewhere, or sign a subordinate CA that runs
elsewhere, so pkid can fit below or above an existing hierarchy.

## Templates

A template describes one kind of certificate: what it is for, how long it
lasts, which keys and names a request can contain, and whether every
request waits for approval. A CA issues only from the templates it is given.

`pki setup` adds two templates:

- **Server**, for TLS servers named by host name. Its certificates last 90
  days.
- **Device**, for client authentication, such as EAP-TLS on Wi-Fi, for
  devices and people named by user principal name or email address. Its
  certificates last a year.

Both let any authenticated principal enroll. Enrolling grants nothing by
itself: the names decide.

## Names

The name trees decide who can request certificates for which names. There
are two trees, one of host names, such as `radius.lab.home`, and one of
principal names, such as `alice@home`. Each name can have its own security
descriptor and its own owner, and names below it inherit its descriptor's
inheritable entries, so a grant on `lab.home` covers every name under it.

Three rights apply to a name:

- **Request** issues certificates for the name without approval.
- **Request with approval** holds them for an officer.
- **Wildcard** also permits the name's wildcard form, such as `*.lab.home`.

A name's owner is the principal it belongs to, such as the RADIUS server's
account for `radius.lab.home`. The roots of both trees grant Request to
PRINCIPAL SELF, which matches a name's owner, so every owner can request its
own names, and Administrators can request any. Nobody else can request
anything until you grant it. A certificate whose names all belong to one
owner carries the owner's SID, so services that accept it for sign-in can
match it to the account rather than to a name that only looks the same.

## Rights on a CA

Each CA's descriptor grants four rights:

- **Read** shows every request and certificate. Without it, a caller sees
  only its own.
- **Request** lets a caller submit requests.
- **Officer** approves and denies held requests and revokes certificates.
  An officer can never approve a request it submitted itself.
- **Manage** changes the CA, signs subordinate CAs, and exports its key.

By default, Authenticated Users can request, and Administrators and SYSTEM
hold every right. `pkid(8)` describes each right and descriptor.

## Revocation

A certificate can be revoked before it expires, such as when its key is
exposed. Each CA publishes a certificate revocation list (CRL) of what it has
revoked, which pki-httpd serves over HTTP at an address written into every
certificate the CA issues, so that software checking a certificate can find
out. pkid renews the list of a CA whose key it keeps; an offline root's list
is renewed by hand, with its passphrase.
[Publishing Revocation Lists](~peios/certificate-authority/publishing-revocation-lists)
explains how.

## Where it is kept

The configuration, the templates, names, and CAs, is in the Registry under
`Machine\Software\Pki`, which `regman` documents value by value. pkid takes a
change up as soon as it is written, but only as a whole: while any part of
the configuration is invalid, pkid issues nothing and says why in its
`pkid.configuration.loaded` event. `pki` checks each change by the same
rules before it writes it.

Requests, certificates, and revocations are in pkid's database. `pki(8)`
documents every command, and `pkid(8)` the service.
