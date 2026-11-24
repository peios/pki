//! PEIOSEAL v1 cases sealed by peios-crypto and by pso, which seals its
//! key files in the same format (PEI-1772). Each must open here, under the
//! passphrase pki-keys makes of the text as typed, so that a change on
//! either side, or to the normalisation, is caught from pki's side too.
//!
//! `tests/vectors/peioseal.vectors` is a copy of pso's
//! `vectors/peioseal.vectors`; take a new copy when pso adds a case.

use crate::passphrase::Passphrase;

struct Case {
    name: String,
    typed: String,
    passphrase: Vec<u8>,
    plaintext: Vec<u8>,
    blob: Vec<u8>,
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hexadecimal");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal"))
        .collect()
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut fields = std::collections::BTreeMap::new();
    for line in include_str!("../tests/vectors/peioseal.vectors").lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line == "end" {
            let mut field = |name: &str| fields.remove(name).unwrap_or_else(|| panic!("no {name}"));
            cases.push(Case {
                name: field("case"),
                typed: field("typed"),
                passphrase: hex(&field("passphrase")),
                plaintext: hex(&field("plaintext")),
                blob: hex(&field("blob")),
            });
            fields.clear();
            continue;
        }
        let (name, value) = line.split_once(' ').expect("a field and its value");
        fields.insert(name.to_owned(), value.to_owned());
    }
    cases
}

#[test]
fn every_case_opens_under_the_passphrase_as_typed() {
    let cases = cases();
    let names: Vec<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    for expected in ["peios-crypto-ascii", "peios-crypto-nfkc", "pso-ascii"] {
        assert!(
            names.contains(&expected),
            "{expected} is missing: {names:?}"
        );
    }
    for case in &cases {
        let passphrase = Passphrase::new(&case.typed);
        assert_eq!(passphrase.bytes(), case.passphrase, "{}", case.name);
        let opened = peios_crypto::open_with_passphrase(&case.blob, passphrase.bytes())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(opened.expose(), case.plaintext, "{}", case.name);
    }
}

#[test]
fn a_case_does_not_open_under_another_passphrase() {
    let case = cases()
        .into_iter()
        .find(|case| case.name == "pso-ascii")
        .unwrap();
    let wrong = Passphrase::new("correct horse battery stapler");
    assert!(peios_crypto::open_with_passphrase(&case.blob, wrong.bytes()).is_err());
}
