use anyhow::{bail, Result};
use clap::Parser;
use landlock::{
  Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
  RulesetCreatedAttr, RulesetStatus, ABI,
};
use serde::Deserialize;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, process};

#[derive(Deserialize, Debug)]
struct Policy {
  read: Vec<String>,
  write: Vec<String>,
  exec: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(long = "type", value_name = "TYPE")]
  pub test_type: String,

  #[clap(long = "name", value_name = "NAME")]
  pub test_name: String,

  #[clap(long = "command", value_name = "CMD")]
  pub command: String,

  #[clap(long = "policy", value_name = "FILE")]
  pub policy: String,
}

const NUM_TESTS: usize = 50;

fn main() -> Result<()> {
  let args = Args::parse();

  if args.test_type == "ebpf" {
    let pid = process::id();
    fs::write("./tmp", format!("{}", pid))?;
    eprintln!("Setup phase ok");
    Command::new("sleep").arg("5").spawn()?.wait()?;
  }

  // --------- Loading the policy from the file

  let policy: Policy = serde_json::from_str(&fs::read_to_string(args.policy)?)?;

  // --------- Applying landlock

  let abi = ABI::V2;
  let mut ruleset = Ruleset::new()
    .handle_access(AccessFs::from_all(abi))?
    .create()?;

  ruleset = ruleset
    .add_rule(PathBeneath::new(PathFd::new(".")?, Access::from_all(abi)))?;

  for path in &policy.read {
    let path_fd = PathFd::new(path)?;
    ruleset =
      ruleset.add_rule(PathBeneath::new(path_fd, AccessFs::from_read(abi)))?;
  }

  for path in &policy.write {
    let path_fd = PathFd::new(path)?;
    ruleset =
      ruleset.add_rule(PathBeneath::new(path_fd, Access::from_write(abi)))?;
  }

  for path in &policy.exec {
    let path_fd = PathFd::new(path)?;
    ruleset = ruleset.add_rule(PathBeneath::new(path_fd, AccessFs::Execute))?;
  }

  let status = ruleset.restrict_self()?;

  if status.ruleset == RulesetStatus::NotEnforced {
    bail!("Landlock not supported by the running kernel!");
  }

  // --------- Running the command

  let parts: Vec<_> = args.command.split_whitespace().collect();
  let mut cmd = Command::new(parts[0]);
  cmd.args(parts.iter().skip(1)).stdout(Stdio::null());

  let times = bench(&mut cmd)?;

  for t in times {
    println!(
      "{},{},{}",
      args.test_name,
      args.test_type.as_str(),
      t.as_secs_f64() * 1000 as f64
    );
  }

  Ok(())
}

fn bench(cmd: &mut Command) -> Result<[Duration; NUM_TESTS]> {
  let mut times = [Duration::ZERO; NUM_TESTS];

  for i in 0..NUM_TESTS {
    if i % 10 == 0 {
      eprintln!("{}...", i)
    }
    let before = Instant::now();
    cmd.spawn()?.wait()?;
    times[i] = before.elapsed();
  }

  Ok(times)
}
