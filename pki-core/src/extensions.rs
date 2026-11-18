//! Certificate extensions rcgen does not provide.

use yasna::models::ObjectIdentifier;
use yasna::Tag;

use crate::names::Sid;

/// Microsoft's SID security extension, `szOID_NTDS_CA_SECURITY_EXT`.
const OID_NTDS_CA_SECURITY_EXT: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 25, 2];
/// The other-name type inside it, `szOID_NTDS_OBJECTSID`.
const OID_NTDS_OBJECTSID: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 25, 2, 1];

/// Encodes the SID security extension that binds a certificate to a
/// principal ([MS-WCCE] 2.2.2.7.7.4).
///
/// Windows and Certipy encode the value as a GeneralNames sequence holding
/// one other-name whose value is the SID's string form in an
/// `[0] EXPLICIT OCTET STRING`. The extension is not critical.
pub(crate) fn sid_extension(sid: &Sid) -> rcgen::CustomExtension {
    rcgen::CustomExtension::from_oid_content(OID_NTDS_CA_SECURITY_EXT, sid_extension_value(sid))
}

fn sid_extension_value(sid: &Sid) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_tagged_implicit(Tag::context(0), |writer| {
                    writer.write_sequence(|writer| {
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(OID_NTDS_OBJECTSID));
                        writer.next().write_tagged(Tag::context(0), |writer| {
                            writer.write_bytes(sid.as_str().as_bytes());
                        });
                    });
                });
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_extension_value_matches_the_windows_encoding() {
        let sid = Sid::new("S-1-5-32-544").unwrap();
        let mut expected = vec![0x30, 0x1e, 0xa0, 0x1c, 0x06, 0x0a];
        expected.extend([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01]);
        expected.extend([0xa0, 0x0e, 0x04, 0x0c]);
        expected.extend(b"S-1-5-32-544");
        assert_eq!(sid_extension_value(&sid), expected);
    }
}
