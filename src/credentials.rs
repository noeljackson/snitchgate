//! Credential values can come from an explicit private file or an environment variable.
use anyhow::{Result, anyhow, ensure};
use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};

const MAX_SECRET: u64 = 65_536;

pub fn read(name: &str) -> Result<String> {
    if let Some(path) = std::env::var_os(format!("{name}_FILE")) {
        // Explicit file configuration takes precedence and fails closed. It never
        // falls back to an unrelated inherited token if the file is unavailable.
        read_file(Path::new(&path))
    } else {
        let value = std::env::var(name)
            .map_err(|_| anyhow!("credential environment variable is unavailable"))?;
        validate(value)
    }
}

fn read_file(path: &Path) -> Result<String> {
    ensure!(path.is_absolute(), "credential file path must be absolute");
    let file = File::open(path).map_err(|_| anyhow!("credential file is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("credential file metadata is unavailable"))?;
    let uid = std::fs::metadata("/proc/self")?.uid();
    let systemd_directory = std::env::var_os("CREDENTIALS_DIRECTORY");
    ensure!(
        metadata.is_file()
            && metadata.len() <= MAX_SECRET
            && ((metadata.uid() == uid && metadata.mode() & 0o077 == 0)
                || systemd_file(path, &metadata, systemd_directory.as_deref().map(Path::new))),
        "credential file must be private and owned by this user or supplied by systemd"
    );
    let mut data = String::new();
    file.take(MAX_SECRET + 1)
        .read_to_string(&mut data)
        .map_err(|_| anyhow!("credential file could not be read"))?;
    validate(data.trim_end_matches(['\r', '\n']).to_owned())
}

fn systemd_file(path: &Path, metadata: &Metadata, directory: Option<&Path>) -> bool {
    let Some(directory) = directory else {
        return false;
    };
    // systemd may use root-owned 0440/0550 files/directories with a named-user
    // read ACL. Group mask bits reflect that ACL, not a generally shared file.
    // Only the explicitly advertised, root-controlled credential directory may
    // use this exception; ordinary root/group-readable files remain rejected.
    if !directory.is_absolute()
        || path.parent() != Some(directory)
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o037 != 0
    {
        return false;
    }
    std::fs::symlink_metadata(directory)
        .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o027 == 0)
}

fn validate(value: String) -> Result<String> {
    ensure!(
        !value.trim().is_empty() && value.len() <= MAX_SECRET as usize && !value.contains('\0'),
        "credential is empty or invalid"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn private_files_are_bounded_and_error_messages_never_include_values() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credential");
        std::fs::write(&path, "fixture-token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_file(&path).unwrap(), "fixture-token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_SECRET as usize + 1]).unwrap();
        assert!(read_file(&path).is_err());
        let error = read_file(&root.path().join("SECRET_SHOULD_NOT_APPEAR")).unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET_SHOULD_NOT_APPEAR"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o440)).unwrap();
        let metadata = path.metadata().unwrap();
        assert!(!systemd_file(&path, &metadata, None));
        assert!(!systemd_file(&path, &metadata, Some(root.path())));
        assert!(!systemd_file(&path, &metadata, Some(Path::new("relative"))));
    }
}
