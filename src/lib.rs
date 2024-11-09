//! [![crates.io](https://img.shields.io/crates/v/karen?logo=rust)](https://crates.io/crates/karen/)
//! [![docs.rs](https://docs.rs/sudo/badge.svg)](https://docs.rs/sudo)
//!
//! Detect if you are running as root, restart self with `sudo` if needed or setup uid zero when running with the SUID flag set.
//!
//! ## Requirements
//!
//! * The `sudo` program is required to be installed and setup correctly on the target system.
//! * Linux or Mac OS X tested
//!     * It should work on *BSD. However, you can also create an Escalate builder with `doas` as the wrapper should you prefer that.
#![allow(clippy::bool_comparison)]

use std::error::Error;
use std::process::Command;

#[macro_use]
extern crate log;

/// Cross platform representation of the state the current program running
#[derive(Debug, PartialEq)]
pub enum RunningAs {
    /// Root (Linux/Mac OS/Unix) or Administrator (Windows)
    Root,
    /// Running as a normal user
    User(u32),
    /// Started from SUID, a call to `karen::escalate_if_needed` or `karen::with_env` is required to claim the root privileges at runtime.
    /// This does not restart the process.
    Suid,
}
use RunningAs::*;

#[cfg(unix)]
/// Check getuid() and geteuid() to learn about the configuration this program is running under
pub fn check() -> RunningAs {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };

    match (uid, euid) {
        (0, 0) => Root,
        (_, 0) => Suid,
        (_, _) => User(uid),
    }
    //if uid == 0 { Root } else { User }
}

/// Helper struct to de/escalate privileges.
///
/// This struct contains helper code to run suid/sgid. It also comes with a normal suid/sgid wrapper without
/// needing to restart the process.
///
/// To suid or sgid without restarting the process, you need to have the CAP_SETUID and CAP_SETGID capabilities set.
///
pub struct Escalate {
    wrapper: String,
    as_user: Option<u32>,
    as_group: Option<u32>,
}

impl Default for Escalate {
    fn default() -> Self {
        Escalate {
            wrapper: "sudo".to_string(),
            as_user: None,
            as_group: None,
        }
    }
}

impl Escalate {
    pub fn builder() -> Self {
        Default::default()
    }

    pub fn wrapper(&mut self, wrapper: &str) -> &mut Self {
        self.wrapper = wrapper.to_string();
        self
    }

    /// Attempt to escalate to specified UID (or root if not specified) without restarting the process.
    pub fn suid(&self) -> Result<RunningAs, Box<dyn Error>> {
        let current = check();
        trace!("Running as {:?}", current);
        match current {
            Root => {
                let uid = self.as_user.unwrap_or(0);
                trace!("setuid({})", uid);
                if uid != 0 {
                    unsafe {
                        if libc::setuid(uid) != 0 {
                            return Err(Box::new(std::io::Error::last_os_error()));
                        }
                    }
                    Ok(Suid)
                } else {
                    Ok(Root)
                }
            }
            Suid | User(_) => {
                let uid = self.as_user.unwrap_or(0);
                trace!("setuid({})", uid);
                unsafe {
                    if libc::setuid(uid) != 0 {
                        return Err(Box::new(std::io::Error::last_os_error()));
                    }
                }
                if uid == 0 {
                    Ok(Root)
                } else {
                    Ok(Suid)
                }
            }
        }
    }

    pub fn as_group(&mut self, group_id: u32) -> &mut Self {
        self.as_group = Some(group_id);
        self
    }

    /// Set the user ID to the specified user
    pub fn as_user(&mut self, user_id: u32) -> &mut Self {
        self.as_user = Some(user_id);
        self
    }

    /// Attempt to escalate to specified GID (or root group if not specified) without restarting the process.
    pub fn sgid(&self) -> Result<RunningAs, Box<dyn Error>> {
        let current = check();
        trace!("Running as {:?}", current);
        match current {
            Root => {
                let gid = self.as_group.unwrap_or(0);
                trace!("setgid({})", gid);
                if gid != 0 {
                    unsafe {
                        if libc::setgid(gid) != 0 {
                            return Err(Box::new(std::io::Error::last_os_error()));
                        }
                    }
                    Ok(Suid)
                } else {
                    Ok(Root)
                }
            }
            Suid | User(_) => {
                let gid = self.as_group.unwrap_or(0);
                trace!("setgid({})", gid);
                unsafe {
                    if libc::setgid(gid) != 0 {
                        return Err(Box::new(std::io::Error::last_os_error()));
                    }
                }
                if gid == 0 {
                    Ok(Root)
                } else {
                    Ok(Suid)
                }
            }
        }
    }

    /// Set the user and group IDs to the specified user and group, respectively without triggering a restart.
    pub fn set_ids(&self) -> Result<RunningAs, Box<dyn Error>> {
        if let Some(_gid) = self.as_group {
            self.sgid()?;
        }
        if let Some(_uid) = self.as_user {
            self.suid()?;
        }

        Ok(check())
    }

    /// Run a function inside suid/sgid scope
    pub fn run_in_scope<F, R>(&self, func: F) -> Result<R, Box<dyn Error>>
    where
        F: FnOnce() -> R,
    {
        let original_uid = unsafe { libc::getuid() };
        let original_gid = unsafe { libc::getgid() };

        self.set_ids()?;

        let result = func();

        unsafe {
            libc::setuid(original_uid);
            libc::setgid(original_gid);
        }

        Ok(result)
    }

    ///  Escalate privileges while maintaining RUST_BACKTRACE and selected environment variables (or none).
    ///
    /// Activates SUID privileges when available.
    pub fn with_env(&self, prefixes: &[&str]) -> Result<RunningAs, Box<dyn Error>> {
        let current = check();
        trace!("Running as {:?}", current);
        match current {
            Root => {
                trace!("already running as Root");
                return Ok(current);
            }
            Suid => {
                let uid = self.as_user.unwrap_or(0);
                trace!("setuid({})", uid);
                if uid != 0 {
                    unsafe {
                        if libc::setuid(uid) != 0 {
                            return Err(Box::new(std::io::Error::last_os_error()));
                        }
                    }
                    return Ok(Suid);
                }
                return Ok(current);
            }
            User(_) => {
                debug!("Escalating privileges");
            }
        }

        let mut args: Vec<_> = std::env::args().collect();
        if let Some(absolute_path) = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|p| p.to_string()))
        {
            args[0] = absolute_path;
        }
        let mut command: Command = Command::new(&self.wrapper);

        // Always propagate RUST_BACKTRACE
        if let Ok(trace) = std::env::var("RUST_BACKTRACE") {
            let value = match &*trace.to_lowercase() {
                "" => None,
                "1" | "true" => Some("1"),
                "full" => Some("full"),
                invalid => {
                    warn!(
                        "RUST_BACKTRACE has invalid value {:?} -> defaulting to \"full\"",
                        invalid
                    );
                    Some("full")
                }
            };
            if let Some(value) = value {
                trace!("relaying RUST_BACKTRACE={}", value);
                command.env("RUST_BACKTRACE", value);
            }
        }

        if !prefixes.is_empty() {
            // Only add env for pkexec if we're passing any additional env vars
            if self.wrapper == "pkexec" {
                trace!("Prefixing `env` to pkexec command to pass additional environment variables! This may break pkexec system policies.");
                command.arg("env");
            }
            for (name, value) in std::env::vars().filter(|(name, _)| name != "RUST_BACKTRACE") {
                if prefixes.iter().any(|prefix| name.starts_with(prefix)) {
                    trace!("propagating {}={}", name, value);
                    if self.wrapper == "pkexec" {
                        command.arg(format!("{}={}", name, value));
                    }
                    command.env(name, value);
                }
            }
        }

        if let Some(user_id) = self.as_user {
            command.arg(format!("--user={}", user_id));
        }

        let mut child = command.args(args).spawn().expect("failed to execute child");

        let ecode = child.wait().expect("failed to wait on child");

        if ecode.success() == false {
            std::process::exit(ecode.code().unwrap_or(1));
        } else {
            std::process::exit(0);
        }
    }
    /// Restart your program with root privileges if the user is not privileged enough.
    ///
    /// Activates SUID privileges when available
    pub fn escalate_if_needed(&self) -> Result<RunningAs, Box<dyn Error>> {
        self.with_env(&[])
    }
}

#[cfg(unix)]
/// Alias for Escalate::builder() to quickly create a new karen Escalate builder
pub fn builder() -> Escalate {
    Escalate::builder()
}

#[cfg(unix)]
/// Restart your program with sudo if the user is not privileged enough.
///
/// Activates SUID privileges when available
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #   if karen::check() == karen::RunningAs::Root {
/// karen::escalate_if_needed()?;
/// // the following gets only executed in privileged mode
/// #   } else {
/// #     eprintln!("not actually testing");
/// #   }
/// #   Ok(())
/// # }
/// ```
#[inline]
pub fn escalate_if_needed() -> Result<RunningAs, Box<dyn Error>> {
    with_env(&[])
}

#[cfg(unix)]
/// Similar to escalate_if_needed, but with pkexec as the wrapper
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #   if karen::check() == karen::RunningAs::Root {
/// karen::pkexec()?;
/// // the following gets only executed in privileged mode
/// #   } else {
/// #     eprintln!("not actually testing");
/// #   }
/// #   Ok(())
/// # }
/// ```
#[inline]
pub fn pkexec() -> Result<RunningAs, Box<dyn Error>> {
    builder().wrapper("pkexec").escalate_if_needed()
}

#[cfg(unix)]
/// Similar to escalate_if_needed, but with doas as the wrapper
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #   if karen::check() == karen::RunningAs::Root {
/// karen::doas()?;
/// // the following gets only executed in privileged mode
/// #   } else {
/// #     eprintln!("not actually testing");
/// #   }
/// #   Ok(())
/// # }
/// ```
#[inline]
pub fn doas() -> Result<RunningAs, Box<dyn Error>> {
    builder().wrapper("doas").escalate_if_needed()
}

#[cfg(unix)]
/// Escalate privileges while maintaining RUST_BACKTRACE and selected environment variables (or none).
///
/// Activates SUID privileges when available.
///
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #   if karen::check() == karen::RunningAs::Root {
/// karen::with_env(&["CARGO_", "MY_APP_"])?;
/// // the following gets only executed in privileged mode
/// #   } else {
/// #     eprintln!("not actually testing");
/// #   }
/// #   Ok(())
/// # }
/// ```
pub fn with_env(prefixes: &[&str]) -> Result<RunningAs, Box<dyn Error>> {
    Escalate::default().with_env(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let c = check();
        assert!(true, "{:?}", c);
    }
}
