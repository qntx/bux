//! `bux logs` — show shim stderr for a VM.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use crate::vm::open_runtime;

/// Arguments for `bux logs`.
#[derive(Args)]
pub struct LogsArgs {
    /// Follow log output (like `tail -f`).
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Number of lines from the end to show (0 = entire file).
    #[arg(long, short = 'n', default_value_t = 0)]
    pub tail: usize,

    /// VM ID, name, or prefix.
    pub target: String,
}

#[cfg(unix)]
pub fn logs(args: &LogsArgs) -> Result<()> {
    let rt = open_runtime()?;
    let handle = rt.get(&args.target)?;
    let info = handle.info();
    let path = handle.log_path();

    if !path.exists() {
        anyhow::bail!(
            "no log file for VM {} at {} (shim may not have written stderr yet)",
            info.id,
            path.display()
        );
    }

    if args.follow {
        follow_file(&path, args.tail)
    } else {
        print_file(&path, args.tail)
    }
}

fn print_file(path: &Path, tail: usize) -> Result<()> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if tail == 0 {
        print!("{data}");
        return Ok(());
    }
    let lines: Vec<&str> = data.lines().collect();
    let start = lines.len().saturating_sub(tail);
    for line in lines.into_iter().skip(start) {
        println!("{line}");
    }
    Ok(())
}

fn follow_file(path: &Path, tail: usize) -> Result<()> {
    print_file(path, if tail == 0 { 100 } else { tail })?;

    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(200));
                if reader_needs_reopen(&mut reader, path) {
                    let mut f = File::open(path)?;
                    f.seek(SeekFrom::End(0))?;
                    reader = BufReader::new(f);
                }
            }
            Ok(_) => {
                print!("{line}");
                let _ = std::io::stdout().flush();
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn reader_needs_reopen(reader: &mut BufReader<File>, path: &Path) -> bool {
    let pos = reader.stream_position().unwrap_or(0);
    let len = fs::metadata(path).map_or(0, |m| m.len());
    pos > len
}
