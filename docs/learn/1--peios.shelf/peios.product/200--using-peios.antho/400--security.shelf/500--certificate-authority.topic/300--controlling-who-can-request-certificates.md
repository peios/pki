---
title: Controlling Who Can Request Certificates
type: how-to
description: Give names owners, grant groups the right to request names with
  or without approval, and change what a template issues and who can use it.
related:
  - peios/certificate-authority/overview
  - peios/certificate-authority/requesting-a-certificate
  - peios/certificate-authority/approving-and-revoking-certificates
---

Change who can request certificates when the defaults don't fit: a server
that is to request its own certificate, a group that is to request names
under a domain, or a kind of certificate that needs an officer's approval.

By default, a name's owner can request certificates for it, Administrators
can request any name, and nobody else can request anything.

## Before you start

- Sign in as a member of Administrators. The name and template commands
  write the Registry under `Machine\Software\Pki`, which only Administrators
  can change.
- Run `pki setup` first, as described in
  [Setting Up a Certificate Authority](~peios/certificate-authority/setting-up-a-certificate-authority).

## Let a principal request its own name

Make the principal the name's owner, by its SID:

```sh
pki name set-owner radius.lab.home S-1-5-21-1-2-3-1105
```

The roots of the name trees grant Request to PRINCIPAL SELF, which matches a
name's owner, so the owner can now request certificates for
`radius.lab.home` without approval. Ownership covers exactly that name, not
the names below it, and certificates for the name carry the owner's SID.

Never make a broad group, such as Users, an owner: every member could then
request certificates for the name. `pki` warns if you do.

## Let every account request its own principal name

Rather than set an owner for each person's principal name, let the accounts
on this machine own theirs. List the domains this machine speaks for:

```sh
pki name domains --set home
```

Now `alice@home`, with no owner of its own, belongs to the account `alice`:
Alice can request certificates for it, such as for signing in to Wi-Fi, and
they carry her account's SID. Nobody else can request it, as PRINCIPAL SELF
matches only its owner. Only the account's name is used, which only an
administrator can change, and a domain not listed is never looked up, so
list only your own. An owner you set with `set-owner` still wins.

## Let a group request names under a domain

Give `lab.home` a descriptor that grants the group Request with approval
(0x2), marked to inherit (CI) so it covers every name below:

```sh
pki name set-security lab.home "D:(A;CI;0x2;;;AU)"
```

Here `AU` is Authenticated Users. Their requests for names under `lab.home`
now wait for an officer of the CA. `pki` adds the entries `lab.home`
inherits from above, so Administrators and owners keep the rights the root
gave them.

A tree's root, `.` or `@`, inherits nothing, so its descriptor replaces the
shipped one whole. `pki` warns if a new root descriptor leaves Administrators
unable to request the names in the tree, or owners unable to request their
own.

Prefer Request with approval for groups. Request (0x1) issues without
anyone looking, so granting it to a broad group lets every member obtain
certificates for those names; `pki` warns when you grant it. Wildcard (0x4)
also permits names such as `*.lab.home`.

To undo the change and let `lab.home` inherit again:

```sh
pki name set-security lab.home --inherit
```

## Hold every certificate of a kind for approval

Set a template's issuance to `approval`, and every request under it waits
for an officer, whatever the names allow:

```sh
pki template set Server --issuance approval
```

## Add a kind of certificate

Create a template from a copy of another and change what differs, such as
a server template whose certificates last 30 days:

```sh
pki template create "Short Server" --from Server --lifetime 30 \
  --renewal-window 10
```

`pki` refuses a template pkid wouldn't load, such as one whose renewal
window isn't shorter than its lifetime. Then let a CA issue from it.
`--template` replaces the CA's list, so give every template it is to keep:

```sh
pki ca set "Home Issuing" --template Server --template Device \
  --template "Short Server"
```

A template's enrollment descriptor decides who can use it at all;
`--enroll-security` changes it.

## Use the Certificate Authority window

The window's **Templates** and **Names** pages make the same changes.
**Who Can Request** opens the permissions editor on a template's or a name's
descriptor; for a name, it shows the entries it inherits from the name above
it. A name's page sets its **Owner**, by account name, and **Inherit
Again…** drops its own permissions. **Principal Domains** is at the top of
**Names**. Each control appears only where your permissions in the Registry
let you change it.

## Check the result

Show a name to see its owner, its descriptor, and where the descriptor comes
from:

```sh
pki name show www.lab.home
```

`www.lab.home` has no settings of its own, so its descriptor is inherited
from `lab.home`. `pki name list` lists the names with settings of their own,
and `pki template show Server` shows a template and the CAs that issue from
it.
