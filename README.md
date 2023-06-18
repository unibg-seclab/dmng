# dmng

`dmng` is a command line tool that helps you collect and manage the
list of filesystem requirements associated with your scripts and
programs. Each requirement is represented with a path and the
read (`R`), write (`W`) and execute (`X`) permissions associated with
its use. The tool currently supports Linux systems.

Why `dmng`? Imagine a scenario in which binaries and scripts are
spawned by a web application through subprocesses. These binaries are
trusted by the developer, but may be potentially buggy and cause
damage to the host system. The idea is that the developer wants to
spawn these binaries in sandboxed subprocesses. `dmng` helps the
developer in the definition of the least privilege policies tailored
for each binary. So the goal is to simplify and speed up policy
development.

How it works? `dmng` leverages `ldd`, `strace` and `permissionsnoop`
(a security observability tool with minimal performance footprint) to
monitor the execution of test cases. For each test case a trace is
produced and stored into a sqlite db. Multiple traces coming from
different test cases are merged in a meaningful way, and are used to
automatically derive a policy template. The template can be either
used as-is, or be further refined by the developer via CLI (see
`dmng -e` to see some examples). Finally, each template can be
serialized in a human-readable, comprehensible policy in JSON format.

## Prerequisites

+ `Go` version 1.20
+ `sqlite3` (you can install it with `make install_binaries`)
+ `permissionsnoop` (see installation instructions in the
  [repository](https://github.com/unibg-seclab/permissionsnoop))

## Quickstart

### Install

Run `make` to install the `dmng` executable on your system (requires
sudo privileges).

### Usage

Run `dmng -h` to see usage info.

Run `dmng -e` to see some examples.

Run `make db` to start an interactive DB session.

### Customize

Install `direnv` and run `direnv allow` in the project directory.

Change the code and run `make` to build `dmng` and deploy it system
wide.

Use the tool.

Run `make db` to start an interactive db session (to manually inspect
the cache).

Uninstall the tool from the system with `make clean`.
