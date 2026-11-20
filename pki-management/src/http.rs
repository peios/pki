//! The URL paths CRLs are published and served at, shared by pkid's
//! publisher, which writes them, and pki-httpd, which serves them, so the
//! two can never disagree about what a path means.

use std::path::PathBuf;

/// The relative file path a URL path names, such as `crl/issuing.crl` for
/// `/crl/issuing.crl`, or nothing unless every segment is plain: letters,
/// digits, `.`, `_`, `-` or `~`, not starting with `.`. A path accepted
/// here can't leave the folder it is resolved in.
pub fn relative_path(path: &str) -> Option<PathBuf> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    let mut relative = PathBuf::new();
    for segment in path.split('/') {
        let plain = !segment.is_empty()
            && !segment.starts_with('.')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-~".contains(&byte));
        if !plain {
            return None;
        }
        relative.push(segment);
    }
    Some(relative)
}

/// The relative file path of an `http` URL's path, or nothing for another
/// scheme, a URL without a path, or one with a query or fragment.
pub fn url_path(url: &str) -> Option<PathBuf> {
    let rest = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &url[7..])?;
    let (_, path) = rest.split_once('/')?;
    if path.contains(['?', '#']) {
        return None;
    }
    relative_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_paths_are_accepted() {
        assert_eq!(
            url_path("http://pki.home/crl/issuing.crl"),
            Some(PathBuf::from("crl/issuing.crl"))
        );
        assert_eq!(
            url_path("HTTP://pki.home:8080/root.crl"),
            Some(PathBuf::from("root.crl"))
        );
        assert_eq!(
            relative_path("/crl/issuing.crl"),
            url_path("http://x/crl/issuing.crl")
        );
        for refused in [
            "https://pki.home/root.crl",
            "ldap://pki.home/cn=root",
            "http://pki.home",
            "http://pki.home/",
            "http://pki.home/../etc/passwd",
            "http://pki.home/crl/./root.crl",
            "http://pki.home/crl//root.crl",
            "http://pki.home/.hidden",
            "http://pki.home/root.crl?x=1",
            "http://pki.home/root%2Ecrl",
            "http://pki.home/a\\b.crl",
        ] {
            assert_eq!(url_path(refused), None, "{refused}");
        }
    }
}
