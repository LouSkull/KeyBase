use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() {
    println!("cargo:rerun-if-changed=builder.rc");
    println!("cargo:rerun-if-changed=assets/keybase-builder.ico");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let Some(rc_exe) = find_resource_compiler() else {
        println!(
            "cargo:warning=Windows resource compiler not found; builder icon metadata was skipped."
        );
        return;
    };

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let res_path = out_dir.join("keybase-builder.res");
    let rc_file = PathBuf::from("builder.rc");

    let status = Command::new(rc_exe)
        .args(["/nologo", "/fo"])
        .arg(&res_path)
        .arg(&rc_file)
        .status();

    match status {
        Ok(code) if code.success() => {
            println!(
                "cargo:rustc-link-arg-bin=keybase-builder={}",
                res_path.display()
            );
        }
        Ok(code) => {
            println!(
                "cargo:warning=Failed to compile builder resources (exit code {:?}); EXE icon metadata was skipped.",
                code.code()
            );
        }
        Err(err) => {
            println!(
                "cargo:warning=Failed to run Windows resource compiler: {err}; EXE icon metadata was skipped."
            );
        }
    }
}

fn find_resource_compiler() -> Option<&'static str> {
    if let Some(path) = find_windows_sdk_rc() {
        let path = path.to_string_lossy().to_string();
        let leaked: &'static str = Box::leak(path.into_boxed_str());
        return Some(leaked);
    }

    for candidate in ["rc.exe", "rc"] {
        if Command::new(candidate)
            .arg("/?")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(candidate);
        }
    }
    None
}

fn find_windows_sdk_rc() -> Option<PathBuf> {
    let roots = [
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files\Windows Kits\10\bin",
    ];
    for root in roots {
        let root = Path::new(root);
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for version_dir in versions {
            for arch in ["x64", "x86", "arm64"] {
                let candidate = version_dir.join(arch).join("rc.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
