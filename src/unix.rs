use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

pub fn to_abstract_namespace(raw_path: &Path) -> Option<PathBuf> {
    raw_path
        .as_os_str()
        .as_encoded_bytes()
        .strip_prefix(b"@")
        .map(|name| {
            let mut path = OsString::new();
            path.push("\0");
            // SAFETY:
            // - fulfills the criteria of from_encoded_bytes_unchecked
            let name = unsafe { OsStr::from_encoded_bytes_unchecked(name) };
            path.push(name);
            PathBuf::from(&path)
        })
}
