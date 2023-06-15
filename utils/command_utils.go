// Copyright (c) 2023 Unibg Seclab (https://seclab.unibg.it)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package utils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// command utils debug flag
var DEBUG_COMMAND bool = false

// details the type associated with a command
type CommandType int

// type of commands
const (
	ELFProgram CommandType = iota
	PosixShellScript
	BourneShellScript
)

// error check shorthand that panics
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// flags associated with WRITE permission (OPEN & OPENAT syscalls)
var rw_flags = map[string]bool{
	"O_WRONLY": true,
	"O_RDWR":   true,
	"O_APPEND": true,
	"O_CREAT":  true}

// flags associated with READ permission (OPEN & OPENAT syscalls)
var ro_flags = map[string]bool{
	"O_RDONLY": true,
	"O_EXCL":   true,
}

// Returns the absolute path associated with the command the user
// wants to run, and a type (`CommandType`) associated with it. Panics
// if the command is not found. Set `verbose` to true if feedback on
// stdout is required.
func GetType(pol int, program string, verbose bool) (string, CommandType) {

	// check if command is found
	which := exec.Command("which", program)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	which.Stdout = &stdout
	which.Stderr = &stderr
	err := which.Run()
	if err != nil {
		fmt.Println("Command not found")
		panic(err)
	}

	// get the path associated with the command
	command_path := strings.TrimSuffix(stdout.String(), "\n")

	// get the type associated with the command path
	var file *exec.Cmd
	// loop to catch all the possible transient links
	for {
		file = exec.Command("file", command_path)
		stdout = bytes.Buffer{}
		file.Stdout = &stdout
		err = file.Run()

		if err != nil {
			fmt.Println("Something went wrong while retrieving the ELF " +
				"with the command path")
			panic(err)
		}

		file_stdout := stdout.String()

		// check whether we end up on a link
		if strings.Contains(file_stdout, "symbolic link") {
			message := strings.Split(stdout.String(), " ")
			// store the permission to execute the link
			AddRequirement(pol, strings.TrimRight(message[0], ":"), 5, LINK) // 5 -> R-X perm
			// update the command path to follow the link
			command_path = strings.TrimRight(message[len(message)-1], "\n")
		} else {
			// handle wrappers and ELF programs outside of
			// the loop
			break
		}
	}

	file_stdout := strings.Split(stdout.String(), " ")
	switch file_stdout[1] {
	case "ELF":
		if verbose {
			fmt.Printf("[*] Program type:\tELF program\n")
		}
		// add the executable to the list of requirements
		AddRequirement(pol,
			strings.Trim(strings.Trim(file_stdout[0], " "), ":"),
			5, // 5 -> R-X perm
			EXECUTABLE)
		return command_path, ELFProgram
	case "POSIX":
		if verbose {
			fmt.Printf("[*] Program type:\tPosix Shell Script\n")
		}
		return command_path, PosixShellScript
	case "Bourne-Again":
		if verbose {
			fmt.Printf("[*] Program type:\tBourne-again Shell Script\n")
		}
		return command_path, BourneShellScript
	default:
		return command_path, -1
	}
}

// Utility to discover ELF programs. Returns the ouput of the LDD
// command pipeline
func LDDPipeline(elf_path string) (bytes.Buffer, bytes.Buffer, error) {
	// setup the ldd command
	ldd := exec.Command("ldd", elf_path)
	// setup the grap command
	grep := exec.Command("grep", "-oE", "(.+/ld-linux.+[ ])|(=>[ ]/.+*[ ])")
	// setup the tr command
	trHead := exec.Command("tr", "-d", "=> ")
	trTail := exec.Command("tr", "-d", " ")
	trTab := exec.Command("tr", "-d", "\t")

	// execute the pipeline and return its result
	return Pipeline(ldd, grep, trHead, trTail, trTab)
}

// Connects multiple `cmd.Command`(s) in a Unix-style pipeline,
// executes the commands and waits for the result
// synchronously. Returns stdout and stderr
func Pipeline(cmds ...*exec.Cmd) (bytes.Buffer, bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if len(cmds) < 1 {
		return bytes.Buffer{}, bytes.Buffer{}, errors.New("No commands" +
			" provided to the exec pipeline")
	}

	// create the pipeline
	last := len(cmds) - 1
	for i, cmd := range cmds[:last] {
		var err error
		if cmds[i+1].Stdin, err = cmd.StdoutPipe(); err != nil {
			return bytes.Buffer{}, bytes.Buffer{}, err
		}
	}

	// get the stdout and stderr of the last command
	cmds[last].Stdout, cmds[last].Stderr = &stdout, &stderr

	// start commands
	for i := last; i >= 0; i-- {
		if err := cmds[i].Start(); err != nil {
			return stdout, stderr, err
		}
	}

	// wait for the results of the commands
	cmds[last].Wait()

	// return the result of the pipeline
	return stdout, stderr, nil
}

// Stores in the profiles-DB the list of transient shared libraries
// associated with the ELF program
func ELFHandler(pol int, cmd string, elf_path string) {

	// use LDD to get the list of libraries
	stdout, _, err := LDDPipeline(elf_path)
	checkErr(err)
	trimStdoud := strings.TrimRight(stdout.String(), "\n")
	// pretty print to console
	transient_libs := strings.Split(trimStdoud, "\n")
	if DEBUG_COMMAND {
		fmt.Println("[D] " + strings.ReplaceAll(stdout.String(), "\n", ":"))
	}
	// add the libs to the profiles-DB
	if len(transient_libs) != 0 {
		perm := 5 // read-only permission
		AddRequirements(pol, &transient_libs, perm, SHARED_LIBS)
	}
}

// Traces the requirements of a `cmd` using the strace
// utility. `command` can be a space separated bash command. Stores
// the requirements found in the profiles DB
func Strace(pol int, cmd string, simulationTime float64) {

	// remove logfiles folder (forces deletion in case of panic)
	removeLogFolder()

	// create the folder to store logfiles
	createLogFolder()

	stime := fmt.Sprintf("%.2f", simulationTime)

	// build the strace command
	var timed_strace = []string{
		"timeout",
		"-s15",
		stime + "s",
		"strace",
		"-o",
		LOG_DIRECTORY + "/foo.trace",
		"-ff",
		"-tt",
		"-e",
		"trace=execve,open,openat,creat,link,mkdir,mkdirat",
	}

	if len(strings.Split(cmd, " ")) > 1 {
		timed_strace = append(timed_strace, strings.Split(cmd, " ")...)
		// use only the name of the command or its alias for
		// the rest of the function
		cmd = strings.Split(cmd, " ")[0]
	} else {
		timed_strace = append(timed_strace, cmd)
	}

	strace_cmd := exec.Command(timed_strace[0], timed_strace[1:]...)
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	strace_cmd.Stderr = &stderr
	strace_cmd.Stdout = &stdout

	// run the strace command
	err := strace_cmd.Run()

	if err != nil {
		if err.Error() != "exit status 124" { // SIGTERM
			if DEBUG_COMMAND {
				fmt.Printf("stdout:\n%v\n\n", stdout.String())
				fmt.Printf("stderr:\n%v\n", stderr.String())
			}
			fmt.Printf("\n`err`:%v\n", err)
			panic("[Error] Something went wrong during the timed-strace command")
		}
	}

	// merge log files
	strace_merge_cmd := exec.Command("strace-log-merge", LOG_DIRECTORY+"/foo.trace")
	stderr = bytes.Buffer{}
	stdout = bytes.Buffer{}
	strace_merge_cmd.Stdout = &stdout
	strace_merge_cmd.Stderr = &stderr

	err = strace_merge_cmd.Run()

	if err != nil {
		if DEBUG_COMMAND {
			fmt.Printf("stdout:\n%v\n\n", stdout.String())
			fmt.Printf("stderr:\n%v\n", stderr.String())
		}
		fmt.Printf("\n`err`:%v\n", err)
		panic("[Error] Something went wrong during the strace-log-merge command")
	}

	if DEBUG_COMMAND {
		fmt.Println(stdout.String())
	}

	// extract requirements and add them to the profiles DB
	extractRequirements(pol, cmd, &stdout)

	// duplicate
	removeLogFolder()
}

// Parses the trace produced by `strace`, and directly adds the
// requirements to the profiles DB. `in` is a pointer to the strace
// bytes.Buffer log
func extractRequirements(pol int, cmd string, in *bytes.Buffer) *bytes.Buffer {

	var out bytes.Buffer
	var syscall int

	scanner := bufio.NewScanner(in)

	var counter int32
	var requirements []PolicyRow

	for scanner.Scan() {
		tokens := scanner.Bytes()
		lines := bytes.Split(tokens, []byte("\n"))
		for _, l := range lines { // scan all the lines in the logfile

			syscall = -1

			// execve=1,open=2,openat=2,creat=3,link=4,mkdir=5

			// get the syscall based on the signature
			if bytes.Contains(l, []byte("execve(")) {
				syscall = 1
			} else if bytes.Contains(l, []byte("open(")) || bytes.Contains(l, []byte("openat(")) {
				syscall = 2
			} else if bytes.Contains(l, []byte("creat(")) {
				syscall = 3
			} else if bytes.Contains(l, []byte("link(")) {
				syscall = 4
			} else if bytes.Contains(l, []byte("mkdir(")) || bytes.Contains(l, []byte("mkdirat(")) {
				syscall = 5
			}

			var args []string
			var pms PolicyRow

			if syscall != -1 {
				args = getSyscallArguments(l)
			}
			if len(args) == 0 {
				continue
			}

			switch syscall {
			case 1: // execve()
				requirement := stripQuotes(args[0])
				pms.Req = requirement
				pms.Perm.R = true
				pms.Perm.X = true

			case 2: // open() & openat() have the same arguments
				requirement := stripQuotes(args[1])
				flags := args[2]
				perm := getPermission_open_syscall(flags)
				// add requirement only if flags are recognized
				if perm != nil {
					pms.Req = requirement
					pms.Perm = *perm
				} else if DEBUG_COMMAND {
					fmt.Printf("OPEN SYSCALL: strace line unrecognized:  %s\n", l)
				}

			case 3: // creat()
				requirement := stripQuotes(args[1])
				var perm Permission
				perm.R = true
				perm.W = true
				pms.Req = requirement
				pms.Perm = perm

			case 4: // link()
				// based on the type of link, there are different functions.
				// maybe will support those in the next releases
			case 5: // mkdir() or mkdirat()
				requirement := stripQuotes(args[0])
				var perm Permission
				perm.R = true
				perm.W = true
				pms.Req = requirement
				pms.Perm = perm
			case -1:
				// do nothing

			}

			// syscall catched
			if syscall != -1 {
				if DEBUG_COMMAND {
					// to print the current line to stdout
					out.Write(l)
					out.Write([]byte("\n"))
				}
				requirements = append(requirements, pms)
				counter += 1
				if counter%10 == 0 {
					fmt.Printf("\033[2K\r[*] Collected %d requirements", counter)
				}

			}
		}
	}

	// update the final count
	fmt.Printf("\033[2K\r[*] Collected %d requirements", counter)
	fmt.Println()

	// add requirements to the profiles DB
	AddStraceRequirements(pol, requirements, STRACE_FILE)

	return &out
}

func getPermission_open_syscall(flags_arg string) *Permission {

	flags := strings.Split(flags_arg, "|")

	var perm Permission

	for _, f := range flags {
		if rw_flags[f] {
			perm.R = true
			perm.W = true
			return &perm
		}
	}

	for _, f := range flags {
		if ro_flags[f] {
			perm.R = true
			return &perm
		}
	}

	// unable to extract the permission from the flags_arg
	return nil
}

// Extracts the arguments of a successful syscall
func getSyscallArguments(prototype []byte) []string {

	prot := string(prototype)

	// check the syscall didn't fail
	if bytes.Contains(prototype, []byte("= -1")) {
		return nil
	}

	left := strings.Index(prot, "(")
	right := strings.Index(prot, ")")

	arguments := strings.Split(prot[left+1:right], ", ")

	// remove shebang
	if len(arguments) >= 1 {
		if strings.HasPrefix(arguments[0], "#!") {
			arguments[0] = strings.TrimPrefix(arguments[0], "#!")
		}
	}

	return arguments
}

func stripQuotes(quotedPath string) string {
	var unquoted string
	if len(quotedPath) > 2 {
		unquoted = quotedPath[1 : len(quotedPath)-1]
	}
	return unquoted
}

// Creates the `LOG_DIRECTORY` to store the log files
func createLogFolder() {
	// create log folder if it doesn't exists
	if _, err := os.Stat(LOG_DIRECTORY); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(LOG_DIRECTORY, os.ModePerm)
		if err != nil {
			panic("Unable to create the `" + LOG_DIRECTORY +
				"` directory, check your permissions")
		}
	}
}

// Removes the `LOG_DIRECTORY` to store the log files
func removeLogFolder() {
	// remove log folder
	err := os.RemoveAll(LOG_DIRECTORY)
	if err != nil {
		panic("Unable to removee the `" + LOG_DIRECTORY +
			"` directory, check your permissions")
	}
}
