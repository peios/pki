#!/bin/bash
# pki's qualification pass on a fresh disposable development VM, run as
# SYSTEM on its console (PEI-1714). It defines the pkid service, provisions
# the machine with `pki setup`, and drives every command group against the
# real pkid. Each step prints its exit status; files to check on the host are
# printed in base64 between markers.
#
# Never run it on a machine whose configuration matters: it replaces pki's
# configuration and creates CAs.
set -u
[[ ${PEIOS_DISPOSABLE_PKI_TEST:-} == yes ]] || { echo 'Requires a fresh disposable guest.' >&2; exit 2; }
runtime=/lcl/radius-dev/current
export PATH=$runtime/bin:$PATH LD_LIBRARY_PATH=$runtime/lib
pkid_sid=S-1-5-80-927106304-3681130234-3843647545-210868499-909250352
ca='Test Issuing'

step() {
    local name=$1
    shift
    echo "=== STEP $name: $*"
    "$@"
    echo "=== RC $name $?"
}

dump() {
    echo "=== FILE $1"
    base64 -w0 "$2"
    echo
    echo "=== END $1"
}

printf 'correct horse battery staple\n' > /tmp/passphrase

# Provisioning, then the service.
step setup pki setup
step setup-again pki setup
step state ls -la /var/state/pki /var/state/pki/keys
# The development VM seeds /var/state for SYSTEM alone. SQLite checks every
# directory on the database's path, so pkid needs to read /var/state's
# attributes (FILE_READ_ATTRIBUTES), and to pass through it (FILE_TRAVERSE).
step var-state sd set /var/state "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;;0x1000a0;;;${pkid_sid})"

# authd makes service accounts' tokens, as in radius's and fservd's guests.
# pkid emits events, which needs SeAuditPrivilege.
reg set -p Machine/Generic/Authn/Policy/Everyone Privileges multi:SeChangeNotifyPrivilege
reg set -p "Machine/Generic/Authn/Policy/$pkid_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
step define-authd svctl definition create authd --set ImagePath=/bin/bash --set Arguments=-c \
    --set "Arguments=export LD_LIBRARY_PATH=$runtime/lib; exec $runtime/bin/authd >/run/authd.log 2>&1" \
    --set Identity=SYSTEM --set Readiness=Notify --set Provides=authn \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeCreateTokenPrivilege \
    --set RequiredPrivileges=SeTcbPrivilege --set RequiredPrivileges=SeRestorePrivilege \
    --set RequiredPrivileges=SeAuditPrivilege
step define svctl definition create pkid --set ImagePath=/bin/bash --set Arguments=-c \
    --set "Arguments=export LD_LIBRARY_PATH=$runtime/lib; exec $runtime/bin/pkid >/run/pkid/log 2>&1" \
    --set Identity=Service --set RuntimeDirectories=pkid --set Requires=authd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
step start svctl start pkid
sleep 2
step status svctl status pkid

# A directory pkid can write, standing in for removable media.
mkdir -p /var/state/pki-media
step media sd set /var/state/pki-media "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;${pkid_sid})"

# CAs.
step list-empty pki ca list
step root pki ca create 'Test Root' --root --key-file /var/state/pki-media/root.key \
    --passphrase-file /tmp/passphrase
step issuing pki ca create "$ca" --issuer 'Test Root' --issuer-passphrase-file /tmp/passphrase \
    --template Server --template Device
step list pki ca list
step list-json pki --json ca list
step show-root pki ca show 'Test Root' --out /tmp/root.pem
step show-issuing pki ca show "$ca"
step export-root pki ca export-key 'Test Root' /tmp/root-export.key \
    --passphrase-file /tmp/passphrase --new-passphrase-file /tmp/passphrase
step keys ls -la /var/state/pki/keys /var/state/pki-media /tmp/root-export.key

# Enrolment, issued at once.
step enroll pki enroll "$ca" Server --dns www.test.home --out /tmp/www.p12 \
    --passphrase-file /tmp/passphrase
step enroll-upn pki enroll "$ca" Device --upn alice@test.home --out /tmp/alice.p12 \
    --passphrase-file /tmp/passphrase

# A template that holds every request for approval.
step template-create pki template create Web --from Server --issuance approval
step ca-set pki ca set "$ca" --template Server --template Device --template Web
step held pki enroll "$ca" Web --dns app.test.home --out /tmp/app.p12 \
    --passphrase-file /tmp/passphrase
step pending pki request list "$ca" --status pending
# The guest has no grep, so bash's own matching picks values out of JSON.
listing=$(pki --json request list "$ca" --status pending)
held=
[[ $listing =~ \"id\":([0-9]+) ]] && held=${BASH_REMATCH[1]}
step approve-own pki request approve "$ca" "$held"
step deny pki request deny "$ca" "$held" --reason 'qualification'
step collect-denied pki enroll "$ca" --request "$held" --key /tmp/app.p12.key --out /tmp/app.p12 \
    --passphrase-file /tmp/passphrase
step requests pki request list "$ca"

# Certificates and revocation.
step certs pki cert list "$ca"
listing=$(pki --json cert list "$ca")
serial=
[[ $listing =~ \"serial\":\"([0-9a-f]+)\" ]] && serial=${BASH_REMATCH[1]}
step revoke pki cert revoke "$ca" "$serial" --reason key-compromise
step revoked pki cert show "$ca" "$serial"
step revoke-again pki cert revoke "$ca" "$serial"

# Names, with the warnings each should give.
step owner-broad pki name set-owner www.test.home S-1-5-32-545
step grant-broad pki name set-security test.home 'D:(A;CI;0x1;;;AU)'
step name-show pki name show www.test.home
step names pki name list
step root-narrow pki name set-security . 'D:(A;CI;0x2;;;AU)'
step root-restore pki name set-security . 'O:SYG:SYD:(A;CI;0x1;;;PS)(A;CI;0x7;;;BA)(A;CI;0x7;;;SY)'
step templates pki template list
step delete-in-use pki template delete Web

# Errors and their statuses.
step missing pki ca show nobody
step usage pki ca create Nameless

# A restart keeps everything.
step restart svctl restart pkid
sleep 2
step list-after-restart pki ca list
step certs-after-restart pki cert list "$ca"

step log cat /run/pkid/log /run/authd.log
dump root.pem /tmp/root.pem
dump www.p12 /tmp/www.p12
dump alice.p12 /tmp/alice.p12
echo "=== QUALIFY DONE"
