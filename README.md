# dmng

`dmng` is a command line tool that helps you collect and manage the
list of file system requirements associated with your application,
scripts and programs. Each requirement is a pair of path and related
permission (read `R`, write `W`, execute `X`). The tool currently
supports Linux systems.

Why `dmng`? Frequently, parts of your application require access to
the file system, depend on native shared libraries, or spawn programs
in subprocesses. You clearly want to support these use cases, but you
may want to introduce sandboxing to mitigate potential vulnerabilities
found in your application code or in the native code the application
relies on. `dmng` helps you in the definition of the least privilege
policies. So the goal is to simplify and speed up policy development.

How it works? `dmng` instruments and monitors the application while a
set of test cases are executed. It collects traces (even for multiple
tests) and stores them into a sqlite db. Then, it uses this
information to derive a policy template. The template can be either
used as-is, or be further customized via CLI (see `dmng -e` to see
some examples). Finally, each template can be serialized in a
human-readable, comprehensible policy in JSON format.

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

### Development

Install `direnv`, run `direnv allow` in the project directory.

Change the code, run `make` to build `dmng` and deploy it system wide.

Use the tool.

Run `make db` to start an interactive db session (to manually inspect
the cache).

Uninstall the tool from the system with `make clean`.
