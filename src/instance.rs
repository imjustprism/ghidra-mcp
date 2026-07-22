use std::path::{Path, PathBuf};
use std::time::Duration;

use sysinfo::{ProcessesToUpdate, System};

pub fn prepare(allow_multiple: bool, detach: bool) {
    if !allow_multiple {
        let n = replace_siblings();
        if n > 0 {
            tracing::info!(replaced = n, "replaced prior ghidra-mcp instance(s)");
            std::thread::sleep(Duration::from_millis(120));
        }
    }
    if !detach {
        watch_parent();
    }
}

fn current_exe() -> Option<PathBuf> {
    std::env::current_exe().ok().map(|p| normalize(&p))
}

fn normalize(p: &Path) -> PathBuf {
    let raw = p.to_path_buf();
    dunce_canonicalize(&raw).map_or(raw, |c| c)
}

fn dunce_canonicalize(p: &Path) -> Option<PathBuf> {
    let c = std::fs::canonicalize(p).ok()?;
    let s = c.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        if let Some(unc) = stripped.strip_prefix("UNC\\") {
            return Some(PathBuf::from(format!(r"\\{unc}")));
        }
        return Some(PathBuf::from(stripped));
    }
    Some(c)
}

fn same_binary(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(windows)]
    {
        a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn replace_siblings() -> usize {
    let Some(me_exe) = current_exe() else {
        tracing::warn!("could not resolve current_exe; skipping sibling replace");
        return 0;
    };
    let Ok(my_pid) = sysinfo::get_current_pid() else {
        return 0;
    };

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut killed = 0usize;
    for (pid, proc) in sys.processes() {
        if *pid == my_pid {
            continue;
        }
        let Some(exe) = proc.exe() else {
            continue;
        };
        let exe = normalize(exe);
        if !same_binary(&exe, &me_exe) {
            continue;
        }
        tracing::info!(pid = %pid.as_u32(), "stopping duplicate ghidra-mcp");
        if proc.kill() {
            killed += 1;
        } else {
            tracing::warn!(pid = %pid.as_u32(), "failed to stop sibling");
        }
    }
    killed
}

fn watch_parent() {
    let Ok(my_pid) = sysinfo::get_current_pid() else {
        return;
    };
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[my_pid]), true);
    let Some(me) = sys.process(my_pid) else {
        return;
    };
    let Some(parent) = me.parent() else {
        tracing::debug!("no parent pid; detach-style run");
        return;
    };
    if parent == my_pid || parent.as_u32() == 0 {
        return;
    }

    tracing::debug!(parent = %parent.as_u32(), "watching parent process");
    tokio::spawn(async move {
        let mut sys = System::new();
        let interval = Duration::from_secs(2);
        loop {
            tokio::time::sleep(interval).await;
            sys.refresh_processes(ProcessesToUpdate::Some(&[parent]), true);
            if sys.process(parent).is_none() {
                tracing::info!(
                    parent = %parent.as_u32(),
                    "parent gone — exiting (no orphan bridge)"
                );
                std::process::exit(0);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_is_stable_for_current_exe() {
        let a = current_exe().expect("exe");
        let b = normalize(&a);
        assert!(same_binary(&a, &b));
    }

    #[test]
    fn pid_roundtrip() {
        let p = sysinfo::Pid::from_u32(42);
        assert_eq!(p.as_u32(), 42);
    }
}
