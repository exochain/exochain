// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-platform custody boundary for node-private files.
//!
//! Every operation verifies an integrity-protecting parent and an owner-only,
//! regular, single-link file. Windows creation denies all handle sharing until
//! inherited ACLs have been replaced, verified, and the private bytes synced.
//! Publication and deletion ultimately use paths; this module revalidates
//! immediately around those operations but does not claim general handle-bound
//! race resistance from the standard-library APIs.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use zeroize::{Zeroize, Zeroizing};

const MAX_INITIAL_PRIVATE_BUFFER: usize = 4096;

struct ZeroizingWriteBuffer {
    bytes: Zeroizing<Vec<u8>>,
    logical_len: usize,
}

impl ZeroizingWriteBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            logical_len: 0,
        }
    }

    fn grow(&mut self, needed: usize) -> std::io::Result<()> {
        let required = self
            .logical_len
            .checked_add(needed)
            .ok_or_else(|| std::io::Error::other("private buffer length overflow"))?;
        if required <= self.bytes.len() {
            return Ok(());
        }
        let next = required
            .max(self.bytes.len().saturating_mul(2))
            .max(MAX_INITIAL_PRIVATE_BUFFER);
        let mut replacement = Zeroizing::new(Vec::new());
        replacement.try_reserve_exact(next)?;
        replacement.resize(next, 0);
        replacement[..self.logical_len].copy_from_slice(&self.bytes[..self.logical_len]);
        self.bytes.zeroize();
        self.bytes = replacement;
        Ok(())
    }

    fn finish(mut self) -> Zeroizing<Vec<u8>> {
        self.bytes.truncate(self.logical_len);
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for ZeroizingWriteBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.logical_len.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for ZeroizingWriteBuffer {}

impl Write for ZeroizingWriteBuffer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.grow(buffer.len())?;
        let end = self.logical_len + buffer.len();
        self.bytes[self.logical_len..end].copy_from_slice(buffer);
        self.logical_len = end;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrivateFileReadError {
    #[error("private file not found: {path}")]
    NotFound { path: PathBuf },
    #[error("{message}: {path}")]
    Rejected {
        path: PathBuf,
        message: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PrivateFileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    len: u64,
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateFileIdentity {
    attributes: u32,
    len: u64,
    owner_sid: String,
}

pub(crate) fn private_temp_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map_or_else(|| OsString::from("private"), OsString::from);
    file_name.push(".tmp");
    path.with_file_name(file_name)
}

fn parent_path(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn current_unix_uid() -> anyhow::Result<u32> {
    static UID: OnceLock<u32> = OnceLock::new();
    if let Some(uid) = UID.get() {
        return Ok(*uid);
    }
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() || output.stdout.len() > 32 || !output.stderr.is_empty() {
        anyhow::bail!("current Unix principal unavailable");
    }
    let rendered = std::str::from_utf8(&output.stdout)?.trim();
    if rendered.is_empty() || !rendered.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("current Unix principal unavailable");
    }
    let uid = rendered.parse::<u32>()?;
    let _ = UID.set(uid);
    Ok(uid)
}

#[cfg(unix)]
fn verify_private_parent(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = parent_path(path);
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_unix_uid()?
        || metadata.mode() & 0o022 != 0
    {
        anyhow::bail!("private parent directory rejected: {}", parent.display());
    }
    Ok(())
}

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(windows)]
const WINDOWS_ACL_TARGET_ENV: &str = "EXOCHAIN_PRIVATE_FILE_ACL_TARGET";

#[cfg(windows)]
const WINDOWS_ACL_PROGRAM: &str = r#"$Target = [Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_ACL_TARGET','Process')
$ErrorActionPreference = 'Stop'
if ([String]::IsNullOrEmpty($Target)) { throw 'private ACL target unavailable' }
$acl = Get-Acl -LiteralPath $Target
$owner = $acl.Owner
try { $owner = ([System.Security.Principal.NTAccount]$owner).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {
    $owner = ([System.Security.Principal.SecurityIdentifier]$owner).Value
}
[Console]::Out.WriteLine('OWNER|' + $owner)
foreach ($ace in $acl.Access) {
    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    [Console]::Out.WriteLine('ACE|' + $sid + '|' + $ace.AccessControlType.ToString() + '|' + $ace.IsInherited.ToString() + '|' + ([int64]$ace.FileSystemRights).ToString())
}"#;

#[cfg(windows)]
#[derive(Debug)]
struct WindowsAce {
    sid: String,
    allow: bool,
    inherited: bool,
    rights: i64,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsAcl {
    owner_sid: String,
    entries: Vec<WindowsAce>,
}

#[cfg(windows)]
fn parse_windows_acl(output: &[u8]) -> anyhow::Result<WindowsAcl> {
    if output.is_empty() || output.len() > 65_536 || output.contains(&0) {
        anyhow::bail!("Windows ACL inspection rejected");
    }
    let text = std::str::from_utf8(output)?;
    let mut lines = text.lines();
    let owner = lines
        .next()
        .and_then(|line| line.strip_prefix("OWNER|"))
        .ok_or_else(|| anyhow::anyhow!("Windows ACL inspection rejected"))?;
    validate_sid(owner)?;
    let mut entries = Vec::new();
    for line in lines {
        let mut fields = line.split('|');
        if fields.next() != Some("ACE") {
            anyhow::bail!("Windows ACL inspection rejected");
        }
        let sid = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("Windows ACL inspection rejected"))?;
        validate_sid(sid)?;
        let access_type = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("Windows ACL inspection rejected"))?;
        let inherited = match fields.next() {
            Some("True") => true,
            Some("False") => false,
            _ => anyhow::bail!("Windows ACL inspection rejected"),
        };
        let rights = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("Windows ACL inspection rejected"))?
            .parse::<i64>()?;
        if fields.next().is_some() || !matches!(access_type, "Allow" | "Deny") {
            anyhow::bail!("Windows ACL inspection rejected");
        }
        entries.push(WindowsAce {
            sid: sid.to_owned(),
            allow: access_type == "Allow",
            inherited,
            rights,
        });
    }
    if entries.is_empty() {
        anyhow::bail!("Windows ACL inspection rejected");
    }
    Ok(WindowsAcl {
        owner_sid: owner.to_owned(),
        entries,
    })
}

#[cfg(windows)]
fn inspect_windows_acl(path: &Path) -> anyhow::Result<WindowsAcl> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_ACL_PROGRAM,
        ])
        .env(WINDOWS_ACL_TARGET_ENV, path)
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        anyhow::bail!("Windows ACL inspection rejected: {}", path.display());
    }
    parse_windows_acl(&output.stdout)
}

#[cfg(windows)]
fn validate_sid(sid: &str) -> anyhow::Result<()> {
    if sid.len() > 184 || !sid.starts_with("S-1-") {
        anyhow::bail!("Windows SID rejected");
    }
    let mut components = sid.split('-');
    if components.next() != Some("S") || components.next() != Some("1") {
        anyhow::bail!("Windows SID rejected");
    }
    let remaining: Vec<&str> = components.collect();
    if remaining.len() < 2
        || remaining
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        anyhow::bail!("Windows SID rejected");
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn parse_whoami_sid(output: &[u8]) -> anyhow::Result<String> {
    if output.is_empty() || output.len() > 4096 || output.contains(&0) {
        anyhow::bail!("current Windows SID unavailable");
    }
    let text = std::str::from_utf8(output)?;
    let line = text.trim_end_matches(['\r', '\n']);
    if line.contains(['\r', '\n']) || !line.starts_with('"') || !line.ends_with('"') {
        anyhow::bail!("current Windows SID unavailable");
    }
    let delimiter = line
        .find("\",\"")
        .ok_or_else(|| anyhow::anyhow!("current Windows SID unavailable"))?;
    if delimiter <= 1 || line[delimiter + 3..line.len() - 1].contains("\",\"") {
        anyhow::bail!("current Windows SID unavailable");
    }
    let sid = &line[delimiter + 3..line.len() - 1];
    validate_sid(sid)?;
    Ok(sid.to_owned())
}

#[cfg(windows)]
pub(crate) fn current_windows_sid() -> anyhow::Result<String> {
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid.clone());
    }
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        anyhow::bail!("current Windows SID unavailable");
    }
    let sid = parse_whoami_sid(&output.stdout)?;
    let _ = SID.set(sid.clone());
    Ok(sid)
}

#[cfg(windows)]
fn verify_private_parent(path: &Path) -> anyhow::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const WRITE_DATA: i64 = 0x0002;
    const APPEND_DATA: i64 = 0x0004;
    const WRITE_EA: i64 = 0x0010;
    const DELETE_CHILD: i64 = 0x0040;
    const WRITE_ATTRIBUTES: i64 = 0x0100;
    const DELETE: i64 = 0x0001_0000;
    const WRITE_DAC: i64 = 0x0004_0000;
    const WRITE_OWNER: i64 = 0x0008_0000;
    const MUTATING_RIGHTS: i64 = WRITE_DATA
        | APPEND_DATA
        | WRITE_EA
        | DELETE_CHILD
        | WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER;

    let parent = parent_path(path);
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        anyhow::bail!("private parent directory rejected: {}", parent.display());
    }
    let sid = current_windows_sid()?;
    let acl = inspect_windows_acl(parent)?;
    if acl.owner_sid != sid
        || acl
            .entries
            .iter()
            .any(|entry| entry.allow && entry.sid != sid && entry.rights & MUTATING_RIGHTS != 0)
    {
        anyhow::bail!("private parent directory rejected: {}", parent.display());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_private_parent(path: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "private parent permission enforcement unavailable: {}",
        parent_path(path).display()
    )
}

#[cfg(unix)]
fn private_identity(metadata: &fs::Metadata) -> PrivateFileIdentity {
    use std::os::unix::fs::MetadataExt;
    PrivateFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        len: metadata.len(),
    }
}

#[cfg(windows)]
fn private_identity(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<PrivateFileIdentity> {
    use std::os::windows::fs::MetadataExt;
    let acl = inspect_windows_acl(path)?;
    Ok(PrivateFileIdentity {
        attributes: metadata.file_attributes(),
        len: metadata.len(),
        owner_sid: acl.owner_sid,
    })
}

#[cfg(unix)]
fn inspect_private_file_with_links(
    path: &Path,
    max_bytes: Option<u64>,
    required_links: u64,
) -> anyhow::Result<PrivateFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    verify_private_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_unix_uid()?
        || !matches!(mode, 0o400 | 0o600)
        || metadata.nlink() != required_links
        || max_bytes.is_some_and(|limit| metadata.len() == 0 || metadata.len() > limit)
    {
        anyhow::bail!("private file rejected: {}", path.display());
    }
    Ok(private_identity(&metadata))
}

#[cfg(unix)]
fn inspect_private_file(
    path: &Path,
    max_bytes: Option<u64>,
) -> anyhow::Result<PrivateFileIdentity> {
    inspect_private_file_with_links(path, max_bytes, 1)
}

#[cfg(windows)]
pub(crate) fn windows_file_is_owner_only(path: &Path, sid: &str) -> anyhow::Result<bool> {
    const FULL_CONTROL: i64 = 2_032_127;
    let acl = inspect_windows_acl(path)?;
    let mut allows = acl.entries.iter().filter(|entry| entry.allow);
    let Some(allow) = allows.next() else {
        return Ok(false);
    };
    Ok(acl.owner_sid == sid
        && allow.sid == sid
        && !allow.inherited
        && allow.rights & FULL_CONTROL == FULL_CONTROL
        && allows.next().is_none())
}

#[cfg(windows)]
fn inspect_private_file(
    path: &Path,
    max_bytes: Option<u64>,
) -> anyhow::Result<PrivateFileIdentity> {
    use std::os::windows::fs::MetadataExt;
    verify_private_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let sid = current_windows_sid()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || max_bytes.is_some_and(|limit| metadata.len() == 0 || metadata.len() > limit)
        || !windows_file_is_owner_only(path, &sid)?
    {
        anyhow::bail!("private file rejected: {}", path.display());
    }
    private_identity(path, &metadata)
}

#[cfg(not(any(unix, windows)))]
fn inspect_private_file(
    path: &Path,
    _max_bytes: Option<u64>,
) -> anyhow::Result<PrivateFileIdentity> {
    anyhow::bail!("private file verification unavailable: {}", path.display())
}

#[cfg(unix)]
fn opened_identity(_path: &Path, file: &File) -> anyhow::Result<PrivateFileIdentity> {
    Ok(private_identity(&file.metadata()?))
}

#[cfg(windows)]
fn opened_identity(path: &Path, file: &File) -> anyhow::Result<PrivateFileIdentity> {
    private_identity(path, &file.metadata()?)
}

pub(crate) fn read_private_file(
    path: &Path,
    max_bytes: u64,
    error_message: &'static str,
) -> Result<Zeroizing<Vec<u8>>, PrivateFileReadError> {
    verify_private_parent(path).map_err(|source| PrivateFileReadError::Rejected {
        path: path.to_path_buf(),
        message: error_message,
        source,
    })?;
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(PrivateFileReadError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(PrivateFileReadError::Rejected {
                path: path.to_path_buf(),
                message: error_message,
                source: source.into(),
            });
        }
    }
    let result = (|| {
        let before = inspect_private_file(path, Some(max_bytes))?;
        let mut file = OpenOptions::new().read(true).open(path)?;
        if opened_identity(path, &file)? != before {
            anyhow::bail!("private file changed before open");
        }
        let capacity = usize::try_from(before.len)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(capacity)?;
        bytes.resize(capacity, 0);
        file.read_exact(bytes.as_mut_slice())?;
        let mut extra = Zeroizing::new([0u8; 1]);
        let grew = file.read(extra.as_mut_slice())? != 0;
        if grew
            || opened_identity(path, &file)? != before
            || inspect_private_file(path, Some(max_bytes))? != before
        {
            anyhow::bail!("private file changed during read");
        }
        Ok(bytes)
    })();
    result.map_err(|source: anyhow::Error| PrivateFileReadError::Rejected {
        path: path.to_path_buf(),
        message: error_message,
        source,
    })
}

#[cfg(windows)]
fn restrict_windows_file(path: &Path) -> anyhow::Result<()> {
    let sid = current_windows_sid()?;
    let grant = format!("*{sid}:(F)");
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .status()?;
    if !status.success() || !windows_file_is_owner_only(path, &sid)? {
        anyhow::bail!("private Windows ACL restriction failed: {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn cleanup_created_empty_windows_file(
    path: &Path,
    expected: &PrivateFileIdentity,
) -> anyhow::Result<()> {
    use std::os::windows::fs::MetadataExt;

    verify_private_parent(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() != 0
        || private_identity(path, &metadata)? != *expected
    {
        anyhow::bail!("created empty private file changed before ACL cleanup");
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_created_windows_file_with<F>(
    path: &Path,
    file: File,
    restrict: F,
) -> anyhow::Result<File>
where
    F: FnOnce(&Path) -> anyhow::Result<()>,
{
    let created = opened_identity(path, &file)?;
    if let Err(error) = restrict(path) {
        let opened_after_error = opened_identity(path, &file);
        drop(file);
        let cleanup = opened_after_error.and_then(|opened| {
            if opened != created || opened.len != 0 {
                anyhow::bail!("created empty private file changed before ACL cleanup");
            }
            cleanup_created_empty_windows_file(path, &opened)
        });
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "private ACL restriction failed: {error}; exact empty-file cleanup failed: {cleanup_error}"
            )),
        };
    }
    Ok(file)
}

fn open_private_create_new(path: &Path) -> anyhow::Result<File> {
    verify_private_parent(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let file = options.open(path).map_err(|error| {
        anyhow::Error::new(error).context(format!(
            "private file creation failed at {}",
            path.display()
        ))
    })?;
    #[cfg(windows)]
    let file = restrict_created_windows_file_with(path, file, restrict_windows_file)?;
    Ok(file)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> anyhow::Result<()> {
    File::open(parent_path(path))?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn cleanup_exact_private_file(path: &Path, expected: &PrivateFileIdentity) -> anyhow::Result<()> {
    if inspect_private_file(path, None)? != *expected {
        anyhow::bail!("private cleanup target changed: {}", path.display());
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

#[cfg(unix)]
fn same_created_file_ignoring_length(
    left: &PrivateFileIdentity,
    right: &PrivateFileIdentity,
) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.mode == right.mode
        && left.owner == right.owner
        && left.links == right.links
}

#[cfg(windows)]
fn same_created_file_ignoring_length(
    left: &PrivateFileIdentity,
    right: &PrivateFileIdentity,
) -> bool {
    left.attributes == right.attributes && left.owner_sid == right.owner_sid
}

fn cleanup_written_private_file(
    path: &Path,
    created: &PrivateFileIdentity,
    opened_after_error: &PrivateFileIdentity,
) -> anyhow::Result<()> {
    if !same_created_file_ignoring_length(created, opened_after_error)
        || inspect_private_file(path, None)? != *opened_after_error
    {
        anyhow::bail!(
            "created private file changed before cleanup: {}",
            path.display()
        );
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

fn write_private_create_new_with<F>(path: &Path, write: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut File) -> std::io::Result<()>,
{
    let mut file = open_private_create_new(path)?;
    let created = opened_identity(path, &file)?;
    let result = (|| {
        write(&mut file)?;
        file.sync_all()?;
        let opened_after_write = opened_identity(path, &file)?;
        let path_after_write = inspect_private_file(path, None)?;
        if !same_created_file_ignoring_length(&created, &opened_after_write)
            || path_after_write != opened_after_write
        {
            anyhow::bail!("private create target changed");
        }
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = result {
        let opened_after_error = opened_identity(path, &file);
        drop(file);
        let cleanup = opened_after_error
            .and_then(|opened| cleanup_written_private_file(path, &created, &opened));
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "private write failed at {}: {error}; cleanup failed: {cleanup_error}",
                path.display()
            )),
        };
    }
    drop(file);
    sync_parent(path)
}

pub(crate) fn write_private_create_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_private_create_new_with(path, |file| file.write_all(bytes))
}

pub(crate) fn write_private_json_create_new<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> anyhow::Result<()> {
    let mut buffer = ZeroizingWriteBuffer::new();
    serde_json::to_writer_pretty(&mut buffer, value)?;
    let bytes = buffer.finish();
    write_private_create_new(path, bytes.as_slice())
}

fn remove_stale_private_temp(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let identity = inspect_private_file(path, None)?;
            cleanup_exact_private_file(path, &identity)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn publish_replace(temp: &Path, destination: &Path) -> anyhow::Result<()> {
    fs::rename(temp, destination)?;
    Ok(())
}

#[cfg(unix)]
fn publish_no_clobber_with_remove<F>(
    temp: &Path,
    destination: &Path,
    expected: &PrivateFileIdentity,
    remove_temp: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    fs::hard_link(temp, destination)?;
    if let Err(error) = remove_temp(temp) {
        let rollback = (|| {
            let temp_linked = inspect_private_file_with_links(temp, None, 2)?;
            let destination_linked = inspect_private_file_with_links(destination, None, 2)?;
            let mut expected_linked = *expected;
            expected_linked.links = 2;
            if temp_linked != expected_linked || destination_linked != expected_linked {
                anyhow::bail!("private no-clobber link pair changed before rollback");
            }
            fs::remove_file(destination)?;
            if inspect_private_file(temp, None)? != *expected {
                anyhow::bail!("private no-clobber temp changed during rollback");
            }
            sync_parent(destination)
        })();
        return match rollback {
            Ok(()) => Err(error.into()),
            Err(rollback_error) => Err(anyhow::anyhow!(
                "private temp unlink failed: {error}; publication rollback failed: {rollback_error}"
            )),
        };
    }
    Ok(())
}

#[cfg(unix)]
fn publish_no_clobber(
    temp: &Path,
    destination: &Path,
    expected: &PrivateFileIdentity,
) -> anyhow::Result<()> {
    publish_no_clobber_with_remove(temp, destination, expected, |path| fs::remove_file(path))
}

#[cfg(windows)]
const WINDOWS_PUBLISH_SOURCE_ENV: &str = "EXOCHAIN_PRIVATE_FILE_PUBLISH_SOURCE";

#[cfg(windows)]
const WINDOWS_PUBLISH_DESTINATION_ENV: &str = "EXOCHAIN_PRIVATE_FILE_PUBLISH_DESTINATION";

#[cfg(windows)]
const WINDOWS_REPLACE_PROGRAM: &str = "$ErrorActionPreference='Stop'; $Source=[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_SOURCE','Process'); $Destination=[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_DESTINATION','Process'); if ([String]::IsNullOrEmpty($Source) -or [String]::IsNullOrEmpty($Destination)) { throw 'private publication path unavailable' }; [System.IO.File]::Replace($Source,$Destination,$null,$true)";

#[cfg(windows)]
const WINDOWS_MOVE_PROGRAM: &str = "$ErrorActionPreference='Stop'; $Source=[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_SOURCE','Process'); $Destination=[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_DESTINATION','Process'); if ([String]::IsNullOrEmpty($Source) -or [String]::IsNullOrEmpty($Destination)) { throw 'private publication path unavailable' }; [System.IO.File]::Move($Source,$Destination)";

#[cfg(windows)]
fn run_windows_publish(program: &str, temp: &Path, destination: &Path) -> anyhow::Result<()> {
    let status = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            program,
        ])
        .env(WINDOWS_PUBLISH_SOURCE_ENV, temp)
        .env(WINDOWS_PUBLISH_DESTINATION_ENV, destination)
        .status()?;
    if !status.success() {
        anyhow::bail!("private Windows publication failed");
    }
    Ok(())
}

#[cfg(windows)]
fn publish_replace(temp: &Path, destination: &Path) -> anyhow::Result<()> {
    run_windows_publish(WINDOWS_REPLACE_PROGRAM, temp, destination)
}

#[cfg(windows)]
fn publish_no_clobber(
    temp: &Path,
    destination: &Path,
    _expected: &PrivateFileIdentity,
) -> anyhow::Result<()> {
    run_windows_publish(WINDOWS_MOVE_PROGRAM, temp, destination)
}

#[cfg(not(any(unix, windows)))]
fn publish_replace(_temp: &Path, _destination: &Path) -> anyhow::Result<()> {
    anyhow::bail!("private replacement unavailable")
}

#[cfg(not(any(unix, windows)))]
fn publish_no_clobber(
    _temp: &Path,
    _destination: &Path,
    _expected: &PrivateFileIdentity,
) -> anyhow::Result<()> {
    anyhow::bail!("private no-clobber publication unavailable")
}

pub(crate) fn write_private_replace(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    verify_private_parent(path)?;
    let existing = match fs::symlink_metadata(path) {
        Ok(_) => Some(inspect_private_file(path, None)?),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let temp = private_temp_path(path);
    remove_stale_private_temp(&temp)?;
    write_private_create_new(&temp, bytes)?;
    let temp_identity = inspect_private_file(&temp, None)?;

    let publish = (|| {
        if inspect_private_file(&temp, None)? != temp_identity {
            anyhow::bail!("private temporary file changed before publication");
        }
        match &existing {
            Some(expected) => {
                if inspect_private_file(path, None)? != *expected {
                    anyhow::bail!("private destination changed before replacement");
                }
                if inspect_private_file(&temp, None)? != temp_identity {
                    anyhow::bail!("private temporary file changed before replacement");
                }
                publish_replace(&temp, path)
            }
            None => match fs::symlink_metadata(path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    if inspect_private_file(&temp, None)? != temp_identity {
                        anyhow::bail!("private temporary file changed before no-clobber move");
                    }
                    publish_no_clobber(&temp, path, &temp_identity)
                }
                Ok(_) => Err(anyhow::anyhow!(
                    "private destination appeared before publication"
                )),
                Err(error) => Err(error.into()),
            },
        }
    })();
    if let Err(error) = publish {
        let cleanup = cleanup_exact_private_file(&temp, &temp_identity);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "private replacement failed at {}: {error}; cleanup failed: {cleanup_error}",
                path.display()
            )),
        };
    }

    let final_identity = inspect_private_file(path, None)?;
    #[cfg(unix)]
    if final_identity.device != temp_identity.device || final_identity.inode != temp_identity.inode
    {
        anyhow::bail!("private replacement result changed");
    }
    #[cfg(windows)]
    if final_identity.owner_sid != temp_identity.owner_sid {
        anyhow::bail!("private replacement result changed");
    }
    sync_parent(path)
}

pub(crate) fn remove_private_file(path: &Path) -> anyhow::Result<()> {
    let before = inspect_private_file(path, None)?;
    if inspect_private_file(path, None)? != before {
        anyhow::bail!("private removal target changed: {}", path.display());
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    #[cfg(unix)]
    use serde::{Serialize, ser::SerializeSeq};

    use super::{
        private_temp_path, read_private_file, write_private_create_new, write_private_replace,
    };
    #[cfg(unix)]
    use super::{
        publish_no_clobber_with_remove, remove_private_file, write_private_create_new_with,
    };

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set test mode");
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path)
            .expect("test metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    #[cfg(unix)]
    #[derive(Debug)]
    struct FailAfterSecret;

    #[cfg(unix)]
    impl Serialize for FailAfterSecret {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element(&"private-growth-marker".repeat(512))?;
            Err(serde::ser::Error::custom(
                "forced private serialization failure",
            ))
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_json_writer_wipes_on_growth_and_serialization_error_before_file_creation() {
        let buffer = super::ZeroizingWriteBuffer::new();
        assert_zeroize_on_drop(&buffer);
        drop(buffer);

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("private.json");
        let error = super::write_private_json_create_new(&path, &FailAfterSecret)
            .expect_err("injected serialization failure");
        assert!(
            error
                .to_string()
                .contains("forced private serialization failure")
        );
        assert!(
            !path.exists(),
            "serialization errors must precede file creation"
        );

        let source = include_str!("private_file.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        let grow = source
            .split("fn grow")
            .nth(1)
            .expect("wipe-before-growth implementation")
            .split("fn finish")
            .next()
            .expect("growth implementation end");
        assert!(grow.contains("self.bytes.zeroize()"));
        assert!(grow.contains("self.bytes = replacement"));
        assert!(grow.find("self.bytes.zeroize()") < grow.find("self.bytes = replacement"));
        assert!(!source.contains("serde_json::to_vec_pretty"));
    }

    #[cfg(unix)]
    #[test]
    fn private_file_create_new_is_owner_only_and_never_clobbers() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("identity.key");

        write_private_create_new(&path, b"first secret").expect("first private create");
        let error = write_private_create_new(&path, b"replacement")
            .expect_err("create-new policy must refuse an existing destination");

        assert!(error.to_string().contains("identity.key"));
        assert_eq!(fs::read(&path).expect("read first secret"), b"first secret");
        assert_eq!(mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_file_partial_write_failure_removes_only_the_same_created_file() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("identity.key");
        let error = write_private_create_new_with(&path, |file| {
            file.write_all(b"partial secret")?;
            Err(std::io::Error::other("forced writer failure"))
        })
        .expect_err("injected partial write must fail");
        assert!(error.to_string().contains("forced writer failure"));
        assert!(!path.exists(), "the exact partial file must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_no_clobber_rolls_back_destination_when_temp_unlink_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("pdp-state.cbor");
        let temp = private_temp_path(&destination);
        write_private_create_new(&temp, b"new private state").expect("private temp");
        let expected = super::inspect_private_file(&temp, None).expect("temp identity");

        let error = publish_no_clobber_with_remove(&temp, &destination, &expected, |_| {
            Err(std::io::Error::other("forced temp unlink failure"))
        })
        .expect_err("injected unlink failure");

        assert!(error.to_string().contains("forced temp unlink failure"));
        assert!(
            temp.exists(),
            "rollback must restore the original temp link"
        );
        assert!(
            !destination.exists(),
            "rollback must remove the published link"
        );
        assert_eq!(
            super::inspect_private_file(&temp, None).expect("restored private temp"),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_file_replace_is_atomic_owner_only_for_absent_and_existing_destinations() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("admin_token");

        write_private_replace(&path, b"first token").expect("initial private replace");
        assert_eq!(mode(&path), 0o600);
        write_private_replace(&path, b"second token").expect("existing private replace");

        assert_eq!(
            fs::read(&path).expect("read replaced token"),
            b"second token"
        );
        assert_eq!(mode(&path), 0o600);
        assert!(!private_temp_path(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_replace_refuses_permissive_destination_before_writing_temp() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("admin_token");
        fs::write(&path, b"legacy token").expect("legacy token");
        set_mode(&path, 0o644);

        let error = write_private_replace(&path, b"new secret")
            .expect_err("permissive existing destination must fail closed");

        assert!(error.to_string().contains("admin_token"));
        assert_eq!(
            fs::read(&path).expect("legacy token survives"),
            b"legacy token"
        );
        assert!(!private_temp_path(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_read_accepts_read_only_parent_but_rejects_untrusted_parent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("pdp.key");
        write_private_create_new(&path, b"private bytes").expect("private create");
        set_mode(directory.path(), 0o755);
        assert_eq!(
            read_private_file(&path, 64, "private read rejected")
                .expect("inherited read-only parent access is safe")
                .as_slice(),
            b"private bytes"
        );

        set_mode(directory.path(), 0o777);
        let error = read_private_file(&path, 64, "private read rejected")
            .expect_err("other-writable parent must be rejected");
        assert!(error.to_string().contains("private read rejected"));
    }

    #[cfg(unix)]
    #[test]
    fn private_file_read_returns_typed_not_found_and_uses_fixed_zeroizing_storage() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("identity.key");
        assert!(matches!(
            read_private_file(&missing, 32, "identity key rejected"),
            Err(super::PrivateFileReadError::NotFound { .. })
        ));

        let source = include_str!("private_file.rs");
        let reader = source
            .split("pub(crate) fn read_private_file")
            .nth(1)
            .expect("private reader")
            .split("#[cfg(windows)]\nfn restrict_windows_file")
            .next()
            .expect("reader ends before Windows restriction");
        assert!(!reader.contains("read_to_end"));
        assert!(!reader.contains("Vec::with_capacity"));
        assert!(reader.contains("try_reserve_exact"));
        assert!(reader.contains("resize(capacity, 0)"));
        assert!(reader.contains("read_exact"));
        assert!(reader.contains("let mut extra = Zeroizing::new([0u8; 1])"));
    }

    #[cfg(unix)]
    #[test]
    fn private_file_read_rejects_permissions_type_links_and_size_before_returning_bytes() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let safe = directory.path().join("safe");
        write_private_create_new(&safe, b"secret").expect("private create");

        set_mode(&safe, 0o644);
        assert!(read_private_file(&safe, 64, "rejected").is_err());
        set_mode(&safe, 0o600);
        assert!(read_private_file(&safe, 3, "rejected").is_err());

        let symlink_path = directory.path().join("symlink");
        symlink(&safe, &symlink_path).expect("create symlink");
        assert!(read_private_file(&symlink_path, 64, "rejected").is_err());

        let directory_path = directory.path().join("directory");
        fs::create_dir(&directory_path).expect("create directory");
        assert!(read_private_file(&directory_path, 64, "rejected").is_err());

        let hardlink_path = directory.path().join("hardlink");
        fs::hard_link(&safe, &hardlink_path).expect("create hard link");
        assert!(read_private_file(&safe, 64, "rejected").is_err());
        assert!(read_private_file(&hardlink_path, 64, "rejected").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_replace_recovers_only_exact_owned_regular_stale_temp() {
        use std::os::unix::fs::symlink;

        let recovered = tempfile::tempdir().expect("temporary directory");
        let recovered_dest = recovered.path().join("pdp-state.cbor");
        let recovered_temp = private_temp_path(&recovered_dest);
        write_private_create_new(&recovered_temp, b"stale exact temp").expect("stale temp");
        write_private_replace(&recovered_dest, b"fresh state").expect("recover stale temp");
        assert_eq!(
            fs::read(&recovered_dest).expect("fresh state"),
            b"fresh state"
        );
        assert!(!recovered_temp.exists());

        let permissive = tempfile::tempdir().expect("temporary directory");
        let permissive_dest = permissive.path().join("pdp-state.cbor");
        let permissive_temp = private_temp_path(&permissive_dest);
        fs::write(&permissive_temp, b"not owned custody").expect("permissive temp");
        set_mode(&permissive_temp, 0o644);
        assert!(write_private_replace(&permissive_dest, b"fresh state").is_err());
        assert!(permissive_temp.exists());

        let linked = tempfile::tempdir().expect("temporary directory");
        let linked_dest = linked.path().join("pdp-state.cbor");
        let linked_temp = private_temp_path(&linked_dest);
        let target = linked.path().join("target");
        write_private_create_new(&target, b"target").expect("target");
        symlink(&target, &linked_temp).expect("stale symlink");
        assert!(write_private_replace(&linked_dest, b"fresh state").is_err());
        assert!(
            fs::symlink_metadata(&linked_temp)
                .expect("symlink preserved")
                .file_type()
                .is_symlink()
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let directory_dest = directory.path().join("pdp-state.cbor");
        let directory_temp = private_temp_path(&directory_dest);
        fs::create_dir(&directory_temp).expect("stale directory");
        assert!(write_private_replace(&directory_dest, b"fresh state").is_err());
        assert!(directory_temp.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_removal_revalidates_owner_only_regular_single_link() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let nonce_path = directory.path().join("signing-nonces.json");
        write_private_create_new(&nonce_path, b"nonce bytes").expect("private nonce");
        remove_private_file(&nonce_path).expect("verified nonce retirement");
        assert!(!nonce_path.exists());

        let target = directory.path().join("target");
        write_private_create_new(&target, b"other bytes").expect("target");
        let linked = directory.path().join("linked-nonces.json");
        symlink(&target, &linked).expect("symlink");
        assert!(remove_private_file(&linked).is_err());
        assert!(target.exists());
        assert!(fs::symlink_metadata(&linked).is_ok());
    }

    #[test]
    fn private_file_windows_paths_never_follow_powershell_command_text() {
        let source = include_str!("private_file.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production private-file source");
        let acl_inspection = source
            .split("fn inspect_windows_acl")
            .nth(1)
            .expect("Windows ACL inspection")
            .split("fn validate_sid")
            .next()
            .expect("Windows ACL inspection boundary");
        assert!(!acl_inspection.contains(".arg(path)"));
        assert!(acl_inspection.contains(".env(WINDOWS_ACL_TARGET_ENV, path)"));

        let publication = source
            .split("fn run_windows_publish")
            .nth(1)
            .expect("Windows publication")
            .split("fn publish_replace")
            .next()
            .expect("Windows publication boundary");
        assert!(!publication.contains(".arg(temp)"));
        assert!(!publication.contains(".arg(destination)"));
        assert!(publication.contains(".env(WINDOWS_PUBLISH_SOURCE_ENV, temp)"));
        assert!(publication.contains(".env(WINDOWS_PUBLISH_DESTINATION_ENV, destination)"));

        assert!(source.contains(
            "[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_ACL_TARGET','Process')"
        ));
        assert!(source.contains(
            "[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_SOURCE','Process')"
        ));
        assert!(source.contains(
            "[Environment]::GetEnvironmentVariable('EXOCHAIN_PRIVATE_FILE_PUBLISH_DESTINATION','Process')"
        ));
    }

    #[test]
    fn private_file_windows_creation_is_exclusive_until_acl_hardening_completes() {
        let source = include_str!("private_file.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production private-file source");
        let creation = source
            .split("fn open_private_create_new")
            .nth(1)
            .expect("private create implementation")
            .split("fn sync_parent")
            .next()
            .expect("private create implementation boundary");

        let exclusive = creation
            .find("options.share_mode(0)")
            .expect("Windows private creation must deny concurrent opens");
        let open = creation
            .find("options.open(path)")
            .expect("private create open");
        let restrict = creation
            .find("restrict_created_windows_file_with")
            .expect("Windows ACL hardening");

        assert!(
            exclusive < open,
            "exclusive sharing must be set before create"
        );
        assert!(
            open < restrict,
            "ACL hardening must follow the exclusive create"
        );
    }

    #[cfg(windows)]
    mod windows {
        use std::{fs::OpenOptions, process::Command};

        use super::*;
        use crate::private_file::{
            WINDOWS_MOVE_PROGRAM, WINDOWS_REPLACE_PROGRAM, current_windows_sid,
            inspect_windows_acl, parse_whoami_sid, restrict_created_windows_file_with,
            run_windows_publish, windows_file_is_owner_only,
        };

        fn harden_parent(path: &Path) {
            let sid = current_windows_sid().expect("current SID");
            let grant = format!("*{sid}:(OI)(CI)(F)");
            let status = Command::new("icacls")
                .arg(path)
                .args(["/inheritance:r", "/grant:r"])
                .arg(grant)
                .status()
                .expect("harden test parent");
            assert!(status.success());
        }

        fn harden_file(path: &Path) {
            let sid = current_windows_sid().expect("current SID");
            let grant = format!("*{sid}:(F)");
            let status = Command::new("icacls")
                .arg(path)
                .args(["/inheritance:r", "/grant:r"])
                .arg(grant)
                .status()
                .expect("harden test file");
            assert!(status.success());
        }

        fn write_injection_probe(directory: &Path, helper_name: &str, sentinel_name: &str) {
            let helper = directory.join(helper_name);
            let source = format!(
                "[IO.File]::WriteAllText((Join-Path $PSScriptRoot '{sentinel_name}'),'injected')"
            );
            fs::write(helper, source).expect("write PowerShell injection helper");
        }

        #[test]
        fn private_file_windows_sid_parser_accepts_exactly_one_bounded_sid() {
            assert_eq!(
                parse_whoami_sid(b"\"DESKTOP\\alice\",\"S-1-5-21-1-2-3-1001\"\r\n")
                    .expect("valid whoami output"),
                "S-1-5-21-1-2-3-1001"
            );
            for malformed in [
                b"\"alice\",\"S-1-5-21-1\"\n\"bob\",\"S-1-5-21-2\"\n".as_slice(),
                b"\"alice\",\"not-a-sid\"\n".as_slice(),
                b"\"alice\",\"S-1-5-21-1\" trailing\n".as_slice(),
                &[b'x'; 4097],
            ] {
                assert!(parse_whoami_sid(malformed).is_err());
            }
        }

        #[test]
        fn private_file_windows_acl_parser_accepts_powershell_boolean_spelling() {
            let acl = super::super::parse_windows_acl(
                b"OWNER|S-1-5-21-1-2-3-1001\r\nACE|S-1-5-21-1-2-3-1001|Allow|False|2032127\r\n",
            )
            .expect("PowerShell ACL output");
            assert_eq!(acl.owner_sid, "S-1-5-21-1-2-3-1001");
            assert_eq!(acl.entries.len(), 1);
            assert!(!acl.entries[0].inherited);
        }

        #[test]
        fn private_file_windows_acl_failure_removes_exact_created_empty_file() {
            let directory = tempfile::tempdir().expect("temporary directory");
            harden_parent(directory.path());
            let path = directory.path().join("identity.key");
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create empty private candidate");

            let error = restrict_created_windows_file_with(&path, file, |_| {
                anyhow::bail!("forced ACL restriction failure")
            })
            .expect_err("forced restriction failure");

            assert!(error.to_string().contains("forced ACL restriction failure"));
            assert!(
                !path.exists(),
                "failed pre-write ACL hardening must not leave a retry-blocking artifact"
            );
        }

        #[test]
        fn private_file_windows_exclusive_create_blocks_pre_hardening_read_handles() {
            use std::{io::Write as _, os::windows::fs::OpenOptionsExt as _};

            const ERROR_SHARING_VIOLATION: i32 = 32;

            let directory = tempfile::tempdir().expect("temporary directory");
            harden_parent(directory.path());
            let inherited = Command::new("icacls")
                .arg(directory.path())
                .args(["/grant", "*S-1-1-0:(OI)(CI)(RX)"])
                .status()
                .expect("grant inherited Everyone read");
            assert!(inherited.success());

            let path = directory.path().join("identity.key");
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).share_mode(0);
            let mut file = options.open(&path).expect("exclusive private create");

            let read_error = OpenOptions::new()
                .read(true)
                .open(&path)
                .expect_err("exclusive create must reject a pre-hardening read handle");
            assert_eq!(
                read_error.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION),
                "concurrent private-file reads must fail with a sharing violation"
            );

            file = restrict_created_windows_file_with(&path, file, |target| {
                super::super::restrict_windows_file(target)
            })
            .expect("ACL hardening must work while the exclusive handle is retained");
            file.write_all(b"private key").expect("write private key");
            file.sync_all().expect("sync private key");
            drop(file);

            let sid = current_windows_sid().expect("current SID");
            assert!(windows_file_is_owner_only(&path, &sid).expect("inspect hardened DACL"));
            assert_eq!(fs::read(&path).expect("read private key"), b"private key");
        }

        #[test]
        fn private_file_windows_create_replace_no_clobber_and_metacharacter_paths() {
            let directory = tempfile::Builder::new()
                .prefix("private & ' [meta] $() ")
                .tempdir()
                .expect("metacharacter directory");
            harden_parent(directory.path());
            let path = directory.path().join("admin & ' [token] $().secret");
            let sid = current_windows_sid().expect("current SID");

            write_private_replace(&path, b"first secret").expect("no-clobber move when absent");
            assert!(windows_file_is_owner_only(&path, &sid).expect("inspect first DACL"));
            write_private_replace(&path, b"second secret").expect("safe File.Replace");
            assert!(windows_file_is_owner_only(&path, &sid).expect("inspect replaced DACL"));
            assert_eq!(fs::read(&path).expect("read replacement"), b"second secret");

            let error = write_private_create_new(&path, b"must not clobber")
                .expect_err("create-new must not replace existing file");
            assert!(error.to_string().contains("admin"));
            assert_eq!(fs::read(&path).expect("still replaced"), b"second secret");
        }

        #[test]
        fn private_file_windows_never_parses_no_whitespace_metacharacter_paths_as_code() {
            let directory = tempfile::Builder::new()
                .prefix("exo-private-path-probe-")
                .tempdir()
                .expect("probe directory");
            harden_parent(directory.path());

            let acl_helper_name = "acl-probe.ps1";
            let acl_sentinel = directory.path().join("acl-injection-sentinel");
            write_injection_probe(directory.path(), acl_helper_name, "acl-injection-sentinel");
            let acl_target = directory.path().join("acl-probe.ps1;#[$()]&'雪.secret");
            fs::write(&acl_target, b"acl secret").expect("write ACL target");
            harden_file(&acl_target);

            assert!(
                !acl_target
                    .to_string_lossy()
                    .chars()
                    .any(char::is_whitespace),
                "the injection regression must not be masked by whitespace quoting"
            );
            inspect_windows_acl(&acl_target).expect("inspect metacharacter ACL target");
            assert!(
                !acl_sentinel.exists(),
                "ACL inspection executed path text as PowerShell source"
            );

            let publish_helper_name = "publish-probe.ps1";
            let publish_sentinel = directory.path().join("publish-injection-sentinel");
            write_injection_probe(
                directory.path(),
                publish_helper_name,
                "publish-injection-sentinel",
            );
            let publish_source = directory.path().join("publish-probe.ps1;#[$()]&'é.source");
            let publish_destination = directory.path().join("destination[$()]&'雪.secret");
            for path in [&publish_source, &publish_destination] {
                assert!(
                    !path.to_string_lossy().chars().any(char::is_whitespace),
                    "the publication regression must not be masked by whitespace quoting"
                );
            }

            fs::write(&publish_source, b"move secret").expect("write move source");
            harden_file(&publish_source);
            run_windows_publish(WINDOWS_MOVE_PROGRAM, &publish_source, &publish_destination)
                .expect("publish distinct source and destination with File.Move");
            assert!(!publish_source.exists());
            assert_eq!(
                fs::read(&publish_destination).expect("read moved destination"),
                b"move secret"
            );
            assert!(
                !publish_sentinel.exists(),
                "File.Move publication executed path text as PowerShell source"
            );

            fs::write(&publish_source, b"replace secret").expect("write replace source");
            harden_file(&publish_source);
            run_windows_publish(
                WINDOWS_REPLACE_PROGRAM,
                &publish_source,
                &publish_destination,
            )
            .expect("publish distinct source and destination with File.Replace");
            assert!(!publish_source.exists());
            assert_eq!(
                fs::read(&publish_destination).expect("read replaced destination"),
                b"replace secret"
            );
            assert!(
                !publish_sentinel.exists(),
                "File.Replace publication executed path text as PowerShell source"
            );
        }

        #[test]
        fn private_file_windows_removes_inherited_everyone_and_rejects_extra_allow() {
            let directory = tempfile::tempdir().expect("temporary directory");
            harden_parent(directory.path());
            let path = directory.path().join("pdp.key");
            let sid = current_windows_sid().expect("current SID");
            let inherited = Command::new("icacls")
                .arg(directory.path())
                .args(["/grant", "*S-1-1-0:(OI)(CI)(RX)"])
                .status()
                .expect("grant inherited Everyone read");
            assert!(inherited.success());

            write_private_create_new(&path, b"private key").expect("harden before write");
            assert!(windows_file_is_owner_only(&path, &sid).expect("inspect hardened DACL"));

            let extra = Command::new("icacls")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .status()
                .expect("grant extra allow");
            assert!(extra.success());
            assert!(!windows_file_is_owner_only(&path, &sid).expect("inspect extra allow"));
            assert!(read_private_file(&path, 64, "rejected").is_err());
        }

        #[test]
        fn private_file_windows_refuses_permissive_existing_before_temp_write() {
            let directory = tempfile::tempdir().expect("temporary directory");
            harden_parent(directory.path());
            let path = directory.path().join("admin_token");
            write_private_create_new(&path, b"legacy").expect("legacy private file");
            let extra = Command::new("icacls")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .status()
                .expect("grant extra allow");
            assert!(extra.success());

            assert!(write_private_replace(&path, b"new secret").is_err());
            assert_eq!(fs::read(&path).expect("legacy survives"), b"legacy");
            assert!(!private_temp_path(&path).exists());
        }
    }
}
