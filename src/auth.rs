//! Explicit Linux session-keyring authentication. Never changes the process environment.
use crate::*;
use std::{cell::RefCell, ffi::OsStr, io::IsTerminal};

#[derive(Debug)]
struct Session {
    config: PathBuf,
    variables: HashMap<String, SecretValue>,
}
thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}
pub(crate) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        SESSION.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(crate) fn enabled() -> bool {
    SESSION.with(|s| s.borrow().is_some())
}

pub(crate) fn initialize(config: Option<&Path>, load: bool) -> Result<Guard> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, load);
        return Err(anyhow!(
            "--session-keyring is currently supported only on Linux"
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let config = match config {
            Some(p) if p.is_absolute() => p.to_path_buf(),
            Some(p) => env::current_dir()?.join(p),
            None => env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
                .ok_or_else(|| anyhow!("cannot locate the user config directory"))?
                .join("opz/manual-auth"),
        };
        let variables = if load {
            decode(&keyring(&config, Store::Read)?.ok_or_else(|| {
                anyhow!("no saved session; run opz --session-keyring auth login")
            })?)?
        } else {
            HashMap::new()
        };
        SESSION.with(|s| *s.borrow_mut() = Some(Session { config, variables }));
        Ok(Guard)
    }
}

fn session_key(name: &str) -> bool {
    name.strip_prefix("OP_SESSION_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}
fn auth_key(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with("OP_SESSION")
        || matches!(
            name.as_ref(),
            "OP_SERVICE_ACCOUNT_TOKEN"
                | "OP_CONNECT_TOKEN"
                | "OP_CONNECT_HOST"
                | "OP_ACCOUNT"
                | "OP_CONFIG_DIR"
                | "OPZ_TEST_AUTH_SESSION"
        )
}
/// Removes inherited AND explicitly assigned auth variables from non-op children.
pub(crate) fn sanitize_child(command: &mut Command) {
    if !enabled() {
        return;
    }
    let keys: Vec<OsString> = env::vars_os()
        .map(|(k, _)| k)
        .chain(command.get_envs().map(|(k, _)| k.to_os_string()))
        .filter(|k| auth_key(k))
        .collect();
    for key in keys {
        command.env_remove(key);
    }
}
pub(crate) fn external_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    sanitize_child(&mut command);
    command
}
pub(crate) fn op_command() -> Command {
    let mut command = external_command("op");
    SESSION.with(|s| {
        if let Some(session) = s.borrow().as_ref() {
            command
                .env("OP_CONFIG_DIR", &session.config)
                .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
                .env("OP_DEBUG", "false")
                .env("SHELL", "/bin/bash");
            for (key, value) in &session.variables {
                command.env(key, value.expose());
            }
        }
    });
    command
}
pub(crate) fn op_status(args: &[String]) -> Result<std::process::ExitStatus> {
    let mut command = op_command();
    command.args(args).stdin(Stdio::null());
    if enabled() {
        let output = command_output_with_timeout(command, "op item edit", op_command_timeout())?;
        let redactor = Redactor::default();
        redactor.write_stdout(&output.stdout)?;
        redactor.write_stderr(&output.stderr)?;
        Ok(output.status)
    } else {
        command
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("failed to run `op item edit`")
    }
}

pub(crate) fn redact(text: &str) -> String {
    SESSION.with(|s| match s.borrow().as_ref() {
        Some(session) => session
            .variables
            .values()
            .fold(text.to_string(), |text, value| {
                text.replace(value.expose(), "[REDACTED]")
            }),
        None => text.to_string(),
    })
}
fn decode(bytes: &[u8]) -> Result<HashMap<String, SecretValue>> {
    let values: HashMap<String, String> =
        serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid saved session"))?;
    if values.len() != 1
        || values
            .iter()
            .any(|(k, v)| !session_key(k) || v.is_empty() || v.chars().any(char::is_whitespace))
    {
        return Err(anyhow!("invalid saved session"));
    }
    Ok(values
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}
fn parse_exports(text: &str) -> Result<HashMap<String, SecretValue>> {
    // Parse data, never evaluate shell output. CLI emits double-quoted base64 session tokens.
    let pattern = Regex::new(r#"^export (OP_SESSION_[A-Za-z0-9_]+)="([A-Za-z0-9_+/=.-]+)";?$"#)?;
    let mut values = HashMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let captures = pattern
            .captures(line)
            .ok_or_else(|| anyhow!("unexpected sign-in output"))?;
        if values
            .insert(captures[1].to_string(), SecretValue::new(&captures[2]))
            .is_some()
        {
            return Err(anyhow!("duplicate session assignment"));
        }
    }
    if values.len() != 1 {
        return Err(anyhow!("sign-in did not return one manual session"));
    }
    Ok(values)
}
fn config() -> Result<PathBuf> {
    SESSION.with(|s| {
        s.borrow()
            .as_ref()
            .map(|s| s.config.clone())
            .ok_or_else(|| anyhow!("auth requires --session-keyring"))
    })
}
pub(crate) fn login() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "run auth login in your own interactive terminal; do not send credentials through chat"
        ));
    }
    let config = config()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if config
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink() || !m.is_dir())
        {
            return Err(anyhow!("unsafe authentication config directory"));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config)?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700))?;
    }
    let out = op_command()
        .args(["account", "list", "--format=json"])
        .output()
        .context("could not list configured accounts")?;
    let accounts: Vec<serde_json::Value> = if out.status.success() {
        serde_json::from_slice(&out.stdout).map_err(|_| anyhow!("invalid account list"))?
    } else {
        return Err(anyhow!("could not list configured accounts"));
    };
    if accounts.len() > 1 {
        return Err(anyhow!(
            "use a dedicated --session-config directory containing a single account"
        ));
    }
    let mut command = op_command();
    if let Some(account) = accounts.first() {
        command.args([
            "signin",
            "--force",
            "--account",
            account["account_uuid"]
                .as_str()
                .ok_or_else(|| anyhow!("account ID missing"))?,
        ]);
    } else {
        command.args(["account", "add", "--signin"]);
    }
    let result = command
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .context("could not start manual sign-in")?;
    if !result.status.success() {
        return Err(anyhow!("manual sign-in failed"));
    }
    let values = parse_exports(
        std::str::from_utf8(&result.stdout).map_err(|_| anyhow!("invalid sign-in output"))?,
    )?;
    let payload: HashMap<_, _> = values
        .iter()
        .map(|(k, v)| (k.clone(), v.expose().to_owned()))
        .collect();
    keyring(&config, Store::Write(&serde_json::to_vec(&payload)?))?;
    SESSION.with(|s| {
        if let Some(s) = s.borrow_mut().as_mut() {
            s.variables = values;
        }
    });
    status()
}
pub(crate) fn status() -> Result<()> {
    let mut command = op_command();
    command.arg("whoami").stdin(Stdio::null());
    let out = command_output_with_timeout(command, "op whoami", op_command_timeout())?;
    if !out.status.success() {
        return Err(anyhow!(
            "manual session unavailable or expired; run opz --session-keyring auth login"
        ));
    }
    println!("Session-keyring authentication ready.");
    Ok(())
}
pub(crate) fn logout() -> Result<()> {
    let config = config()?;
    let stored = keyring(&config, Store::Read)?;
    let revoked = match stored {
        None => true,
        Some(bytes) => match decode(&bytes) {
            Err(_) => false,
            Ok(values) => {
                SESSION.with(|s| {
                    if let Some(s) = s.borrow_mut().as_mut() {
                        s.variables = values;
                    }
                });
                let mut command = op_command();
                command.arg("signout").stdin(Stdio::null());
                command_output_with_timeout(command, "op signout", op_command_timeout())
                    .map(|r| r.status.success())
                    .unwrap_or(false)
            }
        },
    };
    keyring(&config, Store::Delete)?;
    if !revoked {
        return Err(anyhow!("local session removed, but op signout failed; server-side revocation was not confirmed"));
    }
    println!("Manual session signed out and removed from the session keyring.");
    Ok(())
}
enum Store<'a> {
    Read,
    Write(&'a [u8]),
    Delete,
}
fn keyring(config: &Path, action: Store<'_>) -> Result<Option<Vec<u8>>> {
    #[cfg(feature = "test-support")]
    if env::var_os("OPZ_TEST_SCENARIO").is_some() {
        return match action {
            Store::Read => Ok(env::var("OPZ_TEST_AUTH_SESSION")
                .ok()
                .map(String::into_bytes)),
            _ => Ok(None),
        };
    }
    #[cfg(target_os = "linux")]
    {
        use secret_service::{blocking::SecretService, EncryptionType};
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|_| anyhow!("cannot connect to Linux Secret Service"))?;
        // Never fall back to a persistent/default collection or a plaintext file.
        let collection = service
            .get_collection_by_alias("session")
            .map_err(|_| anyhow!("OS session keyring unavailable"))?;
        collection
            .ensure_unlocked()
            .map_err(|_| anyhow!("OS session keyring is locked"))?;
        let config = config
            .to_str()
            .ok_or_else(|| anyhow!("session config path must be UTF-8"))?;
        let attrs = HashMap::from([("application", "opz"), ("config", config)]);
        match action {
            Store::Write(bytes) => {
                collection
                    .create_item(
                        "opz manual CLI session",
                        attrs,
                        bytes,
                        true,
                        "application/json",
                    )
                    .map_err(|_| anyhow!("could not save session to keyring"))?;
                Ok(None)
            }
            Store::Read => {
                let items = collection
                    .search_items(attrs)
                    .map_err(|_| anyhow!("could not search session keyring"))?;
                if items.len() > 1 {
                    return Err(anyhow!("ambiguous session keyring entries"));
                }
                items
                    .first()
                    .map(|i| {
                        i.get_secret()
                            .map_err(|_| anyhow!("could not read session keyring"))
                    })
                    .transpose()
            }
            Store::Delete => {
                for item in collection
                    .search_items(attrs)
                    .map_err(|_| anyhow!("could not search session keyring"))?
                {
                    item.delete()
                        .map_err(|_| anyhow!("could not delete session keyring entry"))?;
                }
                Ok(None)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        if let Store::Write(bytes) = action {
            let _ = bytes.len();
        }
        Err(anyhow!(
            "session keyring is currently supported only on Linux"
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_cli_assignments() {
        let v = parse_exports("export OP_SESSION_example=\"test-canary\"\n# comment").unwrap();
        assert_eq!(v["OP_SESSION_example"].expose(), "test-canary");
        assert!(!format!("{v:?}").contains("test-canary"));
        for bad in [
            "export PATH=\"x\"",
            "export OP_SESSION_x=\"$(id)\"",
            "export OP_SESSION_x=\"x\"; echo x",
            "",
            "export OP_SESSION_x=\"a\"\nexport OP_SESSION_x=\"b\"",
        ] {
            assert!(parse_exports(bad).is_err());
        }
    }
}
