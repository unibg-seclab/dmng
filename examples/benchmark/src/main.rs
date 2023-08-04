use anyhow::{bail, Result};
use clap::Parser;
use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
  pub policy: Option<String>,
}

const NUM_TESTS: usize = 50;

fn main() -> Result<()> {
  let args = Args::parse();

  eprintln!("[*] ({}) {}", args.test_type, args.command);

  match args.test_type.as_str() {
    "none" => {
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
    }

    "landlock" => {
      let mut cmd = Command::new("./target/release/landlock_service");
      cmd
        .args(["--type", args.test_type.as_str()])
        .args(["--name", args.test_name.as_str()])
        .args(["--command", args.command.as_str()])
        .args([
          "--policy",
          args.policy.expect("Missing policy for landlock").as_str(),
        ])
        .stdout(Stdio::inherit());

      cmd.spawn()?.wait()?;
    }

    "ebpf" => {
      let mut cmd = Command::new("./target/release/landlock_service")
        .args(["--type", args.test_type.as_str()])
        .args(["--name", args.test_name.as_str()])
        .args(["--command", args.command.as_str()])
        .args([
          "--policy",
          args.policy.expect("Missing policy for landlock").as_str(),
        ])
        .stdout(Stdio::inherit())
        .spawn()?;

      Command::new("sleep").arg("1").spawn()?.wait()?;

      let pid = fs::read_to_string("./tmp")?;
      eprintln!("Pid is: {}", pid);

      let mut permissionsnoop = Command::new("permissionsnoop")
        .args(["--", pid.as_str()])
        .stdout(Stdio::null())
        .spawn()?;

      eprintln!("Permissionsnoop spawned, go on");
      cmd.wait()?;
      permissionsnoop.kill()?;
    }
    _ => {
      bail!("Invalid test type");
    }
  };

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
