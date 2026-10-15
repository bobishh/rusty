/// Commit baked into the service image. Local builds report no identity.
pub fn build_sha() -> Option<&'static str> {
    option_env!("RUSTY_BUILD_SHA").filter(|value| is_commit_sha(value))
}

/// Digest the running executable, rather than claiming a source tag proves deployed bytes.
pub fn artifact_sha256() -> Option<&'static str> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::sync::OnceLock;
    static DIGEST: OnceLock<Option<String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            let mut file = std::fs::File::open(std::env::current_exe().ok()?).ok()?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 65536];
            loop {
                let count = file.read(&mut buffer).ok()?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            Some(format!("{:x}", digest.finalize()))
        })
        .as_deref()
}

pub fn sdk_sha() -> Option<&'static str> {
    option_env!("RUSTY_SDK_SHA").filter(|value| is_commit_sha(value))
}

fn is_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::is_commit_sha;

    #[test]
    fn accepts_only_lowercase_full_git_revisions() {
        assert!(is_commit_sha(&"a".repeat(40)));
        assert!(is_commit_sha(&"b".repeat(64)));
        assert!(!is_commit_sha("unknown"));
        assert!(!is_commit_sha(&"a".repeat(39)));
        assert!(!is_commit_sha(&"A".repeat(40)));
    }
}
