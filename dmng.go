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

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strings"

	dmng "dmng/utils"

	"github.com/akamensky/argparse"
)

// error check shorthand that panics
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func init() {
	user, err := user.Current()
	checkErr(err)

	PROFILES_FOLDER = "/home/" + user.Username + "/.dmng_profiles"
}

// security profiles folder
var PROFILES_FOLDER string

type Permission = dmng.Permission
type PolicyRow = dmng.PolicyRow
type SecurityProfile = dmng.SecurityProfile
type PolicyIdentifier = dmng.PolicyIdentifier

// parser debug flag
var DEBUG_PARSER bool = false

// active context
var CTX string

// active policy
var POL int

// command
var CMD string

// extended command
var EXTD_CMD string

// permission (mask)
var PERMISSION string

func main() {

	/*
	   CMD LINE PARSER AND ARGUMENTS
	*/

	parser := argparse.NewParser("dmng", "A command line tool to manage the "+
		"requirements associated with a binary (or script)")

	// 1. extended arguments

	debug := parser.Flag("", "debug",
		&argparse.Options{
			Help: "Print additional information to console",
		})
	serialize := parser.String("", "serialize",
		&argparse.Options{
			Required: false,
			Help:     "Serialize the policy to a given filename",
		})
	fixdepth := parser.String("", "fixdepth",
		&argparse.Options{
			Required: false,
			Help: "Update the `max_depth` attribute of a given policy according" +
				" to the content of `Deny`",
		})
	setctx := parser.String("", "setcontext",
		&argparse.Options{
			Required: false,
			Help: "Set the active policy context of a command. A policy context is active" +
				" until it's replaced by another one.",
		})
	getctx := parser.Flag("", "getcontext",
		&argparse.Options{
			Required: false,
			Help:     "Get the active policy context",
		})
	profile := parser.Flag("", "profile",
		&argparse.Options{
			Required: false,
			Help:     "Print to console the profile of a command",
		})

	// 2. abbreviated arguments

	command := parser.String("c", "command",
		&argparse.Options{
			Required: false,
			Help:     "Set the command name",
		})
	add := parser.String("a", "add",
		&argparse.Options{
			Required: false,
			Help:     "Add a requirement (the absolute path) to the active policy",
		})
	remove := parser.String("r", "remove",
		&argparse.Options{
			Required: false,
			Help: "Remove a requirement from the active policy. SQL-like requirement" +
				" patterns supported",
		})
	update := parser.String("u", "update",
		&argparse.Options{
			Required: false,
			Help: "Update the permission associated with a requirement in the active policy." +
				" SQL-like requirement patterns supported",
		})
	permission := parser.String("p", "permission",
		&argparse.Options{
			Required: false,
			Help: "Set the Unix-like permission mask. Valid symbols are `r`, `w`, `x`, `-`." +
				" Order matters",
		})
	deny := parser.Flag("d", "deny",
		&argparse.Options{
			Help: "Flag to add/remove/update a requirement to/from the deny list. To be used" +
				" in conjunction with `--add`, `--remove`, `--update` or `--wipe`",
		})
	inspect := parser.Flag("i", "inspect",
		&argparse.Options{
			Required: false,
			Help:     "Print to console the entries stored by the current policy",
		})
	trace := parser.Selector(
		"t", "trace", []string{"static", "ptrace", "ebpf"},
		&argparse.Options{
			Required: false,
			Help: "Trace program and automatically add its requirements to the active policy. " +
				"Three modes are supported: 'static', 'ptrace' and 'ebpf'",
		},
	)
	simulate := parser.Float("s", "simulate",
		&argparse.Options{
			Required: false,
			Help: "Set dynamic tracing. To be used in conjuction with `--trace`. " +
				"Requires the simulation time in seconds (e.g., 1, 2, 3.5)",
		})
	build := parser.Flag("b", "build",
		&argparse.Options{
			Required: false,
			Help:     "Build the security profile for the active policy",
		})
	goal := parser.Int("g", "goal",
		&argparse.Options{
			Required: false,
			Help: "Set the maximum number of entries in the security profile (default 30)." +
				" To be used in conjunction with `--goal`",
		})
	wipe := parser.Flag("w", "wipe",
		&argparse.Options{
			Required: false,
			Help: "Wipe the entries associated with the active policy. If no other option" +
				" is provided, wipes the whole DB",
		})
	example := parser.Flag("e", "example",
		&argparse.Options{
			Required: false,
			Help:     "Print some usage examples",
		})

	/*
	   READ CMD LINE INPUT
	*/

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Println(parser.Usage(err))
		fmt.Printf("[Error] invalid input\n")
		failure()
	}

	/*
	   UTILITY
	*/

	if *example {
		printUsageInfo()
		success()

	} else {
		createDB()

		if *debug {
			enableDebugMode()
		}

		if *serialize != "" {
			BuildProfiles(*goal, *serialize)
			success()
		}

		if *fixdepth != "" {
			FixPolicy(*fixdepth)
			success()
		}

		if *permission != "" {
			PERMISSION = strings.ToLower(*permission)
		}

		if *command != "" {

			// support also space separated shell commands
			sntzCmd := preprocessCommand(strings.Trim(*command, " "))
			cmdKeywords := strings.Split(sntzCmd, " ")
			CMD = cmdKeywords[0]
			EXTD_CMD = CMD
			if len(cmdKeywords) > 1 {
				EXTD_CMD = strings.Join(cmdKeywords, " ")
			}

			fmt.Printf("[*] Command to trace: `%s`\n", EXTD_CMD)

			if *setctx != "" {
				CTX = *setctx
				updateContext()
				success()
			}

			if *getctx {
				getContext()
				success()

			}

			retrieveActiveContext()

			retrieveActivePolicy()

			if trace != nil {
				switch *trace {
				case "static":
					traceStatic()
				case "ptrace":
					if *simulate <= 0 {
						panic("[Error] Dynamic tracing requires to specify the tracing " +
							"timeframe with the '--simulate' argument")
					}

					tracePtrace(*simulate)
				case "ebpf":
					traceEbpf()
				}
				success()
			} else if *wipe {

				isDeny := *deny

				removeActivePolicy(isDeny)
				success()

			} else if *build {
				BuildSecurityProfile(*goal)
				success()

			} else if *inspect {
				inspectCommand()
				success()

			} else if *profile {
				printProfile()
				success()

			} else if *add != "" {

				// check
				if *remove != "" {
					fmt.Println("[Error] Cannot use `--add` and `--remove` at the same time")
					failure()
				}

				path := *add
				isDeny := *deny

				addPath(path, isDeny)
				success()

			} else if *remove != "" {

				path := *remove
				isDeny := *deny

				removePath(path, isDeny)
				success()

			} else if *update != "" {

				path := *update
				updatePath(path)
				success()

			}

		} else if *wipe {

			wipeDB()
			success()

		} else if *getctx {
			getAvailableContexts()
			success()
		}
	}

	// you shouldn't end up here
	printUsageInfo()
	failure()
}

/*
   UTILITY FUNCTIONS
*/

func success() {
	os.Exit(0)
}

func failure() {
	os.Exit(1)
}

func getContext() {
	c := dmng.GetActiveContext(CMD)
	fmt.Printf("[*] CMD: %s, CTX: %s\n", CMD, c)
}

func getAvailableContexts() {
	data := *dmng.GetAvailableContexts()
	for k, v := range data {
		fmt.Printf("[*] CMD %s: , available CTX: |", k)
		for _, e := range v {
			fmt.Printf(" %s |", e)
		}
		fmt.Println()
	}
}

func printUsageInfo() {

	user, err := user.Current()
	checkErr(err)
	infoPath := "/home/" + user.Username + "/.config/dmng/usage.txt"
	info, err := ioutil.ReadFile(infoPath)
	checkErr(err)
	fmt.Println(string(info))
}

func createDB() {

	// create the database if it doesn't exists
	dmng.CreateDB()
}

func enableDebugMode() {

	// propagate debug mode
	dmng.DEBUG_COMMAND = true
	dmng.DEBUG_DB = true
	dmng.DEBUG_TRUNCATE = true
	dmng.DEBUG_SERIALIZER = true
	DEBUG_PARSER = true
}

func updateContext() {

	// update the profiles-DB cache
	dmng.UpdateCacheContext(CMD, CTX)
	// set a new active policy in the profiles-DB
	dmng.UpdatePolicyContext(CMD, CTX)
	// get the active policy context
	POL = dmng.GetActivePolicyContext(CMD, CTX)

	fmt.Printf("[*] Set CTX: %s, CMD: %s, POL: %d\n", CTX, CMD, POL)
}

func retrieveActiveContext() {

	// get the active context from the profiles-DB
	CTX = dmng.GetActiveContext(CMD)
}

// Preprocesses multi-keywords commands sanitizing file paths
func preprocessCommand(cmd string) string {

	// multi-string check
	keywords := strings.Split(cmd, " ")
	if len(keywords) == 1 {
		return cmd
	}

	var sntzCmd strings.Builder

	// copy program name
	fmt.Fprintf(&sntzCmd, "%s ", keywords[0])

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("[E] Unable to get the current folder")
		failure()
	}

	basicOps := map[string]bool{
		">":  true,
		">>": true,
		"<":  true,
		"<<": true,
		"|":  true,
	}

	// for each token in keywords
	for _, tok := range keywords[1:] {

		_, err := os.Stat(tok)

		// check if tok is file
		if _, ok := basicOps[tok]; !ok && err == nil {

			// make the path global and sanitize it
			if !strings.HasPrefix(tok, "/") {
				tok = cwd + "/" + tok
			}
			tok = path.Clean(tok)
		}

		fmt.Fprintf(&sntzCmd, "%s ", tok)
		// else resolve the file and sanitize it

	}

	return sntzCmd.String()[:len(sntzCmd.String())-1]
}

func retrieveActivePolicy() {

	// get the active policy from the profiles-DB
	POL = dmng.GetActivePolicyContext(CMD, CTX)
}

func tracePtrace(simulationTime float64) {

	// add to the profiles-DB the chain-of-links to the executable
	dmng.GetType(POL, CMD, false)

	fmt.Printf("[*] Tracing command with `ptrace`:\t%s\n", CMD)
	dmng.Strace(POL, EXTD_CMD, simulationTime)
}

func traceEbpf() {

	// add to the profiles-DB the chain-of-links to the executable
	dmng.GetType(POL, CMD, false)

	fmt.Printf("[*] Tracing command with `ebpf`:\t%s\n", CMD)
	dmng.Ebpf(POL, EXTD_CMD)
}

// Retrieves all the requirements found for the given `command` and
// adds them to the profiles-DB
func traceStatic() {

	// get the path and the type associated with the command
	command_path, program_type := dmng.GetType(POL, CMD, true)

	help_wrapper := "[*] Command wrapper found, try the `--simulate` option"
	help_tracepath := "[*] No direct path to the ELF program, try the `--simulate` option"

	// print info to console
	fmt.Printf("[*] Command path:\t%s\n", command_path)
	switch program_type {
	case dmng.ELFProgram:
		// get the transient libraries of an ELF file
		dmng.ELFHandler(POL, CMD, command_path)
	case dmng.BourneShellScript:
		fmt.Println(help_wrapper)
	case dmng.PosixShellScript:
		fmt.Println(help_wrapper)
	case -1:
		// undetermined program type
		fmt.Println(help_tracepath)
	}

	success()
}

func removeActivePolicy(isDeny bool) {

	if isDeny {
		dmng.WipeDenials(POL)
	} else {
		dmng.RemoveCommand(POL, CMD, CTX)
	}
}

// Builds the security profiles for all the commands in the profiles-DB
// and writes the policy file. `goal` is the maximum number of
// permissioned targets in the permission Trie of each policy. `fname`
// is the filename to store the marshaled policy.
func BuildProfiles(goal int, fname string) {

	// for each policy in the profiles-DB
	pids := dmng.GetAllAvailablePolicies()
	// profiles mapping 1:1 policies
	var profiles []SecurityProfile

	// build the security profile for each policy
	for _, pid := range pids {
		// set the vars POL, CMD and CTX
		POL = pid.Pol
		CMD = pid.Cmd
		CTX = pid.Ctx
		profiles = append(profiles, BuildSecurityProfile(goal))
		fmt.Printf("[*] Policy for CMD: %s and CTX: %s created successfully\n", CMD, CTX)
	}

	// ensure the dmng_profiles folder is available
	createProfilesFolder(fname)

	// serialize the policies
	dmng.SerializePolicy(pids, profiles, PROFILES_FOLDER, fname)
	fmt.Printf("[*] Policy serialized to file %s\n", dmng.POLICY_DIR+"/"+fname)
}

// Updates the content of a serialized policy fixing possible errors in
// the `max_depth` attribute. `pname` is the policy name.
func FixPolicy(pname string) {

	dmng.FixDepth(PROFILES_FOLDER, pname)
	fmt.Printf("[*] Policy %s updated successfully\n", dmng.POLICY_DIR+"/"+pname)
}

// Builds the security profile of a command, possibly reducing the
// cardinality of requirements to less than or equal to `goal`. Returns
// the entries in the profile created
func BuildSecurityProfile(goal int) SecurityProfile {

	if goal < 0 {
		fmt.Println("[Error] Invalid number of permissions (goal) found")
		failure()
	}
	if goal == 0 {
		// set default value
		goal = 50
	}

	var lof []PolicyRow
	// retrieve requirements
	lof = dmng.GetCommandRequirements(POL)

	// build command Trie
	commandTrie := dmng.CreateTrie(CMD, lof)

	if DEBUG_PARSER {
		fmt.Printf("[D] Initial number of permissioned nodes: %d\n",
			commandTrie.CountPermissionedNodes())
	}

	// print Trie before pruning
	var profile_buffer bytes.Buffer
	if DEBUG_PARSER {
		fmt.Println("[D] Print Trie:")
		commandTrie.PrintTrie(&profile_buffer, 0)
		fmt.Print(profile_buffer.String())
	}

	// prune Trie
	successful_pruning := commandTrie.PruneTrie(goal)

	// print Trie after pruning
	if DEBUG_PARSER {
		fmt.Println("[D] Print Trie:")
		profile_buffer = bytes.Buffer{}
		commandTrie.PrintTrie(&profile_buffer, 0)
		fmt.Print(profile_buffer.String())
	}

	if !successful_pruning {
		fmt.Printf("[W] Pruning goal not achieved "+
			"(still %d nodes)!\n", commandTrie.CountPermissionedNodes())
	}

	if dmng.DEBUG_TRUNCATE {
		// print new profile permissions
		fmt.Printf("[*] New %s profile created successfully\n", CMD)
		profile_buffer = bytes.Buffer{}
		commandTrie.PrintTrieProfile(&profile_buffer)
		fmt.Print(profile_buffer.String())
	}

	// wipe old security profile
	dmng.WipeSecurityProfile(POL)

	// retrieve the new security profile and save it into the profiles-DB
	sp := SecurityProfile{}
	commandTrie.GetSecurityProfile(&sp.Entries)
	dmng.CreateSecurityProfile(POL, &sp.Entries)

	return sp
}

// Creates the policy folder. Removes the old policy serialization
// (`fname`) if present
func createProfilesFolder(fname string) {
	// check if the dmng_profiles directory already exists
	if _, err := os.Stat(PROFILES_FOLDER); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(PROFILES_FOLDER, 0750)
		if err != nil {
			panic("Unable to create the `" + PROFILES_FOLDER +
				"` directory, check your permissions")
		}
	} else {
		err := os.Remove(dmng.POLICY_DIR + "/" + fname)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
	}
	// check folder permissions
	err := os.Chmod(PROFILES_FOLDER, 0750)
	checkErr(err)
}

func printProfile() {

	rows := dmng.GetSecurityProfile(POL)

	fmt.Printf("[*] Security profile CTX: %s, CMD: %s, POL: %d\n", CTX, CMD, POL)

	for i, r := range rows {
		fmt.Printf(" %d,\t%s,\t%s\n", i, r.Perm.ToString(), r.Req)
	}
}

func inspectCommand() {

	// apply mask filter if provided
	if PERMISSION != "" {
		if !dmng.IsValidMask(PERMISSION) {
			fmt.Println("[Error] Invalid permission or permission mask found")
			failure()
		}

		fmt.Printf("[*] Inspect command %s, mask %s\n", CMD, PERMISSION)
		fmt.Printf("\n  Permissions (CTX: %s, POL: %d):\n", CTX, POL)

		dmng.PrintPermissionedRequirements(POL, PERMISSION)
	} else {
		mask := "___ => ANY"

		fmt.Printf("[*] Inspect command %s, mask %s\n", CMD, mask)
		fmt.Printf("\n  Permissions (CTX: %s, POL: %d):\n", CTX, POL)

		// print the requirements
		dmng.PrintRequirements(POL)
	}

	// print the denials
	fmt.Printf("\n  Denials (CTX: %s, POL: %d):\n", CTX, POL)
	dmng.PrintDenials(POL)

}

// Adds a path to the list of requirements of deny
func addPath(path string, isDeny bool) {

	// check path
	if !dmng.IsValidRequirement(path) {
		fmt.Println("[Error] Invalid requirement (file or directory not found)")
		failure()
	}

	if isDeny {
		if PERMISSION != "" {
			fmt.Println("[Error] Permission not needed with a deny.")
			failure()
		}

		dmng.AddDenial(POL, path)
		fmt.Println("[*] Denial for command " + CMD + " added")
	} else {
		if !dmng.IsValidPerm(PERMISSION) {
			fmt.Println("[Error] Invalid permission found")
			failure()
		}

		perm := int(dmng.InitPermission(PERMISSION).ToUnixInt())
		dmng.AddRequirement(POL, path, perm, dmng.USER_INPUT)

		fmt.Println("[*] Requirement of command " + CMD + " added")
	}

}

// Removes a path from the list of requirements or deny
func removePath(path string, isDeny bool) {

	if isDeny {
		// check
		if PERMISSION != "" {
			fmt.Println("[Error] Permission not needed with a deny.")
			failure()
		}

		dmng.RemoveDenial(POL, path)

		fmt.Println("[*] Denial for command " + CMD + " removed")
	} else {
		if PERMISSION == "" {
			fmt.Println("[Error] `--remove` without permission regex is unsupported, use `--wipe` instead")
			failure()
		} else {
			// check permission regex is valid
			if !dmng.IsValidPerm(PERMISSION) {
				fmt.Println("[Error] Invalid permission or permission regex found")
				failure()
			}

			perm := int(dmng.InitPermission(PERMISSION).ToUnixInt())

			// NB we don't check path to be a valid SQL pattern
			dmng.RemovePermissionedRequirements(POL, path, perm)
		}
	}

}

// Updates a path in the list of requirements
func updatePath(path string) {

	// check
	if PERMISSION != "" {
		if !dmng.IsValidPerm(PERMISSION) {
			fmt.Println("[Error] Invalid permission found")
			failure()
		}
		perm := int(dmng.InitPermission(PERMISSION).ToUnixInt())

		// NB, we don't check *update to be a valid SQL pattern
		dmng.UpdateRequirementPermission(POL, path, perm)
	} else {
		fmt.Println("[Error] A permission is required if you want to perform an update")
		failure()
	}
}

func wipeDB() {
	// wipe profiles-DB
	dmng.WipeProfiles()
}
