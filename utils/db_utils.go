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
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

/*
   `cmd` is a string representing the command or binary application
   (eg. `ls` binary should be associated with the "ls" string) *

   `req` is a string representing the path of a requirement of a
   command (eg. the `ls` cmd has `/lib/x86_64-linux-gnu/libc.so.6` as
   a req)
*/

// db utils debug flag
var DEBUG_DB bool = false

// directory to store the profiles
var DB_DIRECTORY string

// profiles-DB path
var DB_NAME string

// log files folder
var LOG_DIRECTORY string

// automatically executed at package import time (do not call)
func init() {
	user, err := user.Current()
	checkErr(err)

	DB_DIRECTORY = "/home/" + user.Username + "/.config/dmng/profiles"
	DB_NAME = "/home/" + user.Username + "/.config/dmng/profiles/profiles-DB.sql"
	LOG_DIRECTORY = "/home/" + user.Username + "/.config/dmng/logs"
}

type PolicyRow struct {
	Req    string
	Perm   Permission
	Origin string
}

type SecurityProfile struct {
	Entries []PolicyRow
}

type PolicyIdentifier struct {
	Pol int
	Cmd string
	Ctx string
}

// origin of the requirement
var LINK string = "LINK"
var EXECUTABLE string = "EXECUTABLE"
var SHARED_LIBS string = "SHARED_LIB"
var USER_INPUT string = "USER_INPUT_FILE"
var STRACE_FILE string = "STRACE_FILE"
var PRUNING_RX string = "PRUNING_RX"
var PRUNING_RW string = "PRUNING_RW"
var EXCEPTION string = "EXCEPTION"

// creates the profiles-DB database in a hidden local folder
func CreateDB() {
	// check if the DB already exists
	if !checkDBExists() {
		// if not, create the DB
		// 1. create the DB file
		db_file, err := os.Create(DB_NAME)
		if err != nil {
			fmt.Println(err)
			panic("Unable to create the profiles-DB, " +
				"check your permissions")
		}
		db_file.Close()
		// 2. open DB
		profiles_db, err := sql.Open("sqlite3", DB_NAME)
		defer profiles_db.Close()
		if err != nil {
			panic("Couldn't open `" + DB_NAME + "`")
		}
		// 3. create tables
		createTables(profiles_db)
	}
}

// returns `true` if the profiles-DB exists. Creates its directory and
// returns `false` if not. Panics if the current process doesn't have
// the required permissions
func checkDBExists() bool {
	// check if the .profiles directory already exists
	if _, err := os.Stat(DB_DIRECTORY); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(DB_DIRECTORY, os.ModePerm)
		if err != nil {
			panic("Unable to create the `" + DB_DIRECTORY +
				"` directory, check your permissions")
		}
		return false
	}
	// check if the DB already exists
	if _, err := os.Stat(DB_NAME); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

// Creates the required tables in the profiles-DB. Receives as input
// an open DB
func createTables(db *sql.DB) {

	// DB SCHEMA

	// CACHE(CMD, ctx)
	create_cache := `CREATE TABLE CACHE (` +
		`"cmd" text NOT NULL PRIMARY KEY,` +
		`"ctx" text NOT NULL);`
	// POLICY(POL, cmd, ctx)
	create_policy := `CREATE TABLE POLICY (` +
		`"pol" integer NOT NULL PRIMARY KEY AUTOINCREMENT,` +
		`"cmd" text NOT NULL,` +
		`"ctx" text NOT NULL,` +
		`UNIQUE("cmd", "ctx"));`
	// RULE(RULE, pol, req, perm, origin)
	create_rule := `CREATE TABLE RULE (` +
		`"rule" integer NOT NULL PRIMARY KEY AUTOINCREMENT,` +
		`"pol" integer NOT NULL,` +
		`"req" text NOT NULL,` +
		`"perm" integer NOT NULL,` +
		`"origin" text NOT NULL);`
	// DENY(DENY, pol, req)
	create_deny := `CREATE TABLE DENY (` +
		`"deny" integer NOT NULL PRIMARY KEY AUTOINCREMENT,` +
		`"pol" integer NOT NULL,` +
		`"req" text NOT NULL, ` +
		`UNIQUE("pol", "req"));`
	// PROFILE(ID, pol, req, perm)
	create_profile := `CREATE TABLE PROFILE (` +
		`"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,` +
		`"pol" integer NOT NULL,` +
		`"req" text NOT NULL,` +
		`"perm" integer NOT NULL);`

	stm1, err := db.Prepare(create_cache)
	if err != nil {
		panic("[Error] while preparing the create `CACHE` table statement")
	}
	stm2, err := db.Prepare(create_policy)
	if err != nil {
		panic("[Error] while preparing the create `POLICY` table statement")
	}
	stm3, err := db.Prepare(create_rule)
	if err != nil {
		panic("[Error] while preparing the create `RULE` table statement")
	}
	stm4, err := db.Prepare(create_deny)
	if err != nil {
		panic("[Error] while preparing the create `DENY` table statement")
	}
	stm5, err := db.Prepare(create_profile)
	if err != nil {
		panic("[Error] while preparing the create `PROFILE` table statement")
	}

	_, err = stm1.Exec()
	if err != nil {
		fmt.Println(err)
		panic("[Error] while creating the `CACHE` table")
	}
	_, err = stm2.Exec()
	if err != nil {
		fmt.Println(err)
		panic("[Error] while creating the `POLICY` table")
	}
	_, err = stm3.Exec()
	if err != nil {
		fmt.Println(err)
		panic("[Error] while creating the `RULE` table")
	}
	_, err = stm4.Exec()
	if err != nil {
		fmt.Println(err)
		panic("[Error] while creating the `DENY` table")
	}
	_, err = stm5.Exec()
	if err != nil {
		fmt.Println(err)
		panic("[Error] while creating the `PROFILE` table")
	}

	fmt.Println("[*] Profiles DB created successfully")
}

// Updates the cache in the profiles-DB.
func UpdateCacheContext(cmd string, ctx string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// removal of old cache entry
	pop_cache_query := `DELETE FROM CACHE WHERE cmd = ?;`
	pop_stmt, err := profiles_db.Prepare(pop_cache_query)
	if err != nil {
		panic("[Error] while preparing the `pop_cache` statement")
	}
	// cache pop
	_, err = pop_stmt.Exec(cmd)
	if err != nil {
		panic("[Error] (`pop_cache`)")
	}

	// inserction of new cache entry
	push_cache_query := `INSERT INTO CACHE VALUES (?, ?);`
	push_stmt, err := profiles_db.Prepare(push_cache_query)
	if err != nil {
		panic("[Error] while preparing the `push_cache` statement")
	}
	// cache push
	_, err = push_stmt.Exec(cmd, ctx)
	if err != nil {
		panic("[Error] (`push_cache`)")
	}
}

// Updates the active policy in the profiles-DB.
func UpdatePolicyContext(cmd string, ctx string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// insertion of new policy entry
	pol_ins_query := `INSERT OR IGNORE INTO POLICY (cmd, ctx) VALUES (?, ?);`
	ins_stmt, err := profiles_db.Prepare(pol_ins_query)
	if err != nil {
		panic("[Error] while preparing the `pol_ins` statement")
	}
	// policy insertion
	_, err = ins_stmt.Exec(cmd, ctx)
	if err != nil {
		panic("[Error] (`pol_ins`)")
	}
}

// Returns the identifier of the context (`ctx`) from the profiles-DB.
func GetActiveContext(cmd string) string {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the get ctx statement
	get_ctx_query := `SELECT ctx FROM CACHE WHERE cmd == ?;`
	get_ctx_stmt, err := profiles_db.Prepare(get_ctx_query)
	if err != nil {
		panic("[Error] while preparing the `get_ctx` statement")
	}
	// get the ctx value
	res, err := get_ctx_stmt.Query(cmd)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// print to stdout
	for res.Next() {
		var ctx string
		res.Scan(&ctx)
		return ctx
	}

	panic("[Error] `get_ctx` query, no active context set")
}

// Returns the contexts available for each command
func GetAvailableContexts() *map[string][]string {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the get ctx statement
	get_ctx_query := `SELECT cmd, ctx FROM POLICY;`
	get_ctx_stmt, err := profiles_db.Prepare(get_ctx_query)
	if err != nil {
		panic("[Error] while preparing the `get_ctx` statement")
	}
	// get the ctx value
	res, err := get_ctx_stmt.Query()
	if err != nil {
		panic(err)
	}
	defer res.Close()

	cmds := make(map[string]bool)
	data := make(map[string][]string)

	// print to stdout
	for res.Next() {
		var cm, ct string
		res.Scan(&cm, &ct)
		if _, ok := cmds[cm]; !ok {
			cmds[cm] = true
			data[cm] = []string{}
		}
		data[cm] = append(data[cm], ct)
	}

	return &data
}

// Returns the identifier of the active policy (`pol`) from the
// profiles-DB.
func GetActivePolicyContext(cmd string, ctx string) int {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the get policy statement
	get_pol_query := `SELECT pol FROM POLICY WHERE cmd == ? and ctx == ?;`
	get_pol_stmt, err := profiles_db.Prepare(get_pol_query)
	if err != nil {
		panic("[Error] while preparing the `get_pol` statement")
	}
	// get the policy value
	res, err := get_pol_stmt.Query(cmd, ctx)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// print to stdout
	for res.Next() {
		var pol int
		res.Scan(&pol)
		return pol
	}

	panic("[Error] `get_pol` query, no policy identifier found")
}

// Returns the identifiers of all the available policies in the
// profiles-DB
func GetAllAvailablePolicies() []PolicyIdentifier {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the get ctx statement
	get_pol_query := `SELECT * FROM POLICY;`
	get_pol_stmt, err := profiles_db.Prepare(get_pol_query)
	if err != nil {
		panic("[Error] while preparing the `get_pol` statement")
	}
	// get the ctx value
	res, err := get_pol_stmt.Query()
	if err != nil {
		panic(err)
	}
	defer res.Close()

	identifiers := []PolicyIdentifier{}

	// print to stdout
	for res.Next() {
		identifier := PolicyIdentifier{}
		res.Scan(&identifier.Pol, &identifier.Cmd, &identifier.Ctx)
		identifiers = append(identifiers, identifier)
	}

	return identifiers
}

// Adds a list of `reqs` of a `pol` to the profiles-DB
func AddRequirements(pol int, reqs *[]string, perm int,
	origin string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare bulk query string
	var bld strings.Builder
	counter := 0
	fmt.Fprintf(&bld, "%s", "INSERT INTO RULE(pol, req, perm, origin) VALUES ")
	for _, path := range *reqs {
		fmt.Fprintf(&bld, "(%d, '%s', %d, '%s'),", pol, path, perm, origin)
		counter += 1
	}
	bulk_ins_query := bld.String()[:bld.Len()-1]

	// prepare the insert statement
	insert_stmt, err := profiles_db.Prepare(bulk_ins_query)
	if err != nil {
		panic("[Error] while preparing the insert statement")
	}

	_, err = insert_stmt.Exec()
	if err != nil {
		panic("[Error] during requirement insertion")
	}

	// insertion post process
	ruleTablePostProcessing(profiles_db, pol)

	fmt.Printf("[*] List of requirements of policy %d added\n", pol)
}

// Removes the duplicates keeping only the highest permission for each
// (pol, req) entry
func ruleTablePostProcessing(db *sql.DB, pol int) {
	// 1. for each path, keep only the highest perm (different
	// permissions for the same path could be set by different
	// insertion methods)
	remove_leastp_query := `DELETE FROM RULE WHERE rule IN ( ` +
		`SELECT R.rule from RULE R WHERE R.perm < ` +
		`(SELECT max(perm) from RULE WHERE req=R.req AND pol=R.pol AND pol=?)` +
		`);`
	remove_leastp_stmt, err := db.Prepare(remove_leastp_query)
	if err != nil {
		panic("[Error] while preparing the `remove_leastp` statement")
	}
	_, err = remove_leastp_stmt.Exec(pol)
	if err != nil {
		panic("[Error] (`remove_leastp`)")
	}

	// 2. removal of duplicates (don't want the user to set the
	// same permission for (pol, req))
	remove_dups_query := `DELETE FROM RULE WHERE rule NOT IN ` +
		`(SELECT rule FROM RULE GROUP BY pol, req, perm);`
	remove_dups_stmt, err := db.Prepare(remove_dups_query)
	if err != nil {
		panic("[Error] while preparing the `remove_dups` statement")
	}
	_, err = remove_dups_stmt.Exec()
	if err != nil {
		panic("[Error] (`remove_dups`)")
	}

}

// Adds a single `req` of a `pol` to the profiles-DB.
func AddRequirement(pol int, req string, perm int, origin string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the insert statement
	insert_query := `INSERT INTO RULE(pol, req, perm, origin) ` +
		`VALUES (?,?,?,?);`
	insert_stmt, err := profiles_db.Prepare(insert_query)
	if err != nil {
		panic("[Error] while preparing the insert statement")
	}

	// insert the values
	_, err = insert_stmt.Exec(pol, req, perm, origin)
	if err != nil {
		panic("[Error] during requirement insertion")
	}

	// post processing
	ruleTablePostProcessing(profiles_db, pol)

	fmt.Printf("[*] Requirement of policy %d added\n", +pol)
}

// Adds a single `req` for `pol` in the deny list.
func AddDenial(pol int, req string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the insert statement
	insert_query := `INSERT INTO DENY(pol, req) ` +
		`VALUES (?,?);`
	insert_stmt, err := profiles_db.Prepare(insert_query)
	if err != nil {
		panic("[Error] while preparing the insert statement")
	}

	// insert the values
	_, err = insert_stmt.Exec(pol, req)
	if err != nil {
		panic("[Error] during deny insertion")
	}

	fmt.Printf("[*] Denial of policy %d added\n", +pol)
}

// Removes a single `req` for `pol` in the deny list.
func RemoveDenial(pol int, req string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	delete_query := `DELETE FROM DENY WHERE pol == ? AND req LiKE ?;`
	delete_stmt, err := profiles_db.Prepare(delete_query)
	if err != nil {
		panic("[Error] while preparing the delete statement")
	}

	// delete the values
	_, err = delete_stmt.Exec(pol, req)
	if err != nil {
		panic("[Error] during deny removal")
	}

	fmt.Printf("[*] Denial of policy %d removed\n", +pol)
}

// Wipes all the entries associated with `pol` in the deny list.
func WipeDenials(pol int) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	delete_query := `DELETE FROM DENY WHERE pol == ?;`
	delete_stmt, err := profiles_db.Prepare(delete_query)
	if err != nil {
		panic("[Error] while preparing the delete statement")
	}

	// wipe the entries
	_, err = delete_stmt.Exec(pol)
	if err != nil {
		panic("[Error] during deny removal")
	}

	fmt.Printf("[*] Denials associated with policy %d wiped\n", +pol)
}

// Adds a list of `requirements` of a `command` to the
// profiles-DB. This is function is used after `command` has been
// traced. Each `requirements` entry is a struct containing the path
// of the requirement and the associated Permission. Avoids the
// insertion of duplicates
func AddStraceRequirements(pol int, requirements []PolicyRow,
	origin string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare bulk query string
	var bld strings.Builder
	counter := 0
	fmt.Fprintf(&bld, "%s", "INSERT INTO RULE(pol, req, perm, origin) VALUES ")
	for _, req := range requirements {
		fmt.Fprintf(&bld, "(%d, '%s', %d, '%s'),", pol, req.Req, req.Perm.ToUnixInt(), origin)
		counter += 1
	}
	bulk_ins_query := bld.String()[:bld.Len()-1]

	// prepare the insert statement
	insert_stmt, err := profiles_db.Prepare(bulk_ins_query)
	if err != nil {
		panic("[Error] while preparing the insert statement")
	}

	_, err = insert_stmt.Exec()
	if err != nil {
		panic("[Error] during requirement insertion")
	}

	fmt.Printf("[*] Perfomed %d insertions to the profiles-DB", counter)
	fmt.Println()

	// remove duplicates from DB
	ruleTablePostProcessing(profiles_db, pol)

	fmt.Println("[*] List of requirements provided by strace added")
}

// Prints to stdout all the requirements of an active policy
func PrintRequirements(pol int) {
	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the query
	select_query := `SELECT req, perm, origin FROM RULE WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// print to stdout
	for res.Next() {
		var rperm int
		var rreq, rorig string
		res.Scan(&rreq, &rperm, &rorig)
		perm := IntToPermission(rperm).ToString()
		fmt.Printf("    %s | %s | %s\n", rreq, perm, rorig)
	}
}

// Prints to stdout all the denials stored in the active policy
func PrintDenials(pol int) {
	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the query
	select_query := `SELECT req FROM DENY WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// print to stdout
	for res.Next() {
		var rreq string
		res.Scan(&rreq)
		fmt.Printf("    %s\n", rreq)
	}
}

// Returns all the denials associated with the current policy
func GetDenials(pol int) []PolicyRow {
	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the query
	select_query := `SELECT req FROM DENY WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	rows := []PolicyRow{}

	for res.Next() {
		var rreq string
		res.Scan(&rreq)
		pr := PolicyRow{}
		pr.Req = rreq
		rows = append(rows, pr)
	}

	return rows
}

// Prints to stdout all the requirements of a policy matching the
// permission mask.
func PrintPermissionedRequirements(pol int, perm_mask string) {
	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the query
	select_query := `SELECT * FROM RULE WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// print to stdout
	for res.Next() {
		var rrule, rpol, rperm int
		var rreq, rorig string
		res.Scan(&rrule, &rpol, &rreq, &rperm, &rorig)
		// convert the int permission to `Permission` type
		perm := IntToPermission(rperm)
		// print the requirement only if the permission matches the mask
		if perm.PermissionMatch(perm_mask) {
			fmt.Printf("    %d | %d | %s | %s | %s\n", rrule, rpol, rreq, perm.ToString(), rorig)
		}
	}
}

// removes a list of `requirements` of a `command` from the
// profiles-DB. `requirements` supports sql regexes
func RemoveRequirements(command string,
	requirements *[]string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	delete_query := `DELETE FROM REQUIREMENT ` +
		`WHERE command_name == ? AND requirement_path LIKE ?;`
	delete_stmt, err := profiles_db.Prepare(delete_query)
	if err != nil {
		panic("[Error] while preparing the delete statement")
	}

	// remove the values
	for _, path := range *requirements {
		_, err = delete_stmt.Exec(command, path)
		if err != nil {
			panic("[Error] during requirement deletion")
		}
	}
	fmt.Println("[*] List of requirements of command `" + command +
		"` removed")
}

// Removes all the requirements matching `req_regex` and `perm` of a
// policy from the profiles-DB.
func RemovePermissionedRequirements(pol int, req_regex string, perm int) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	delete_query := `DELETE FROM RULE ` +
		`WHERE pol == ? AND req LIKE ? AND perm == ?;`
	delete_stmt, err := profiles_db.Prepare(delete_query)
	if err != nil {
		panic("[Error] while preparing the delete statement")
	}

	// removal
	_, err = delete_stmt.Exec(pol, req_regex, perm)
	if err != nil {
		panic("[Error] during requirement deletion")
	}

	fmt.Printf("[*] List of requirements of policy %d deleted\n", pol)
}

// Removes the entries related to the active policy for `command`.
func RemoveCommand(pol int, command string, ctx string) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statements
	wipe_cache := `DELETE FROM CACHE WHERE cmd == ? AND ctx == ?;`
	wipe_policy := `DELETE FROM POLICY WHERE pol == ?;`
	wipe_rule := `DELETE FROM RULE WHERE pol == ?;`
	wipe_deny := `DELETE FROM DENY WHERE pol == ?;`

	w_cache_stmt, err := profiles_db.Prepare(wipe_cache)
	if err != nil {
		panic("[Error] while preparing the wipe cache statement")
	}

	w_policy_stmt, err := profiles_db.Prepare(wipe_policy)
	if err != nil {
		panic("[Error] while preparing the wipe policy statement")
	}

	w_rule_stmt, err := profiles_db.Prepare(wipe_rule)
	if err != nil {
		panic("[Error] while preparing the wipe rule statement")
	}

	w_deny_stmt, err := profiles_db.Prepare(wipe_deny)
	if err != nil {
		panic("[Error] while preparing the wipe deny statement")
	}

	// remove the values
	_, err = w_cache_stmt.Exec(command, ctx)
	if err != nil {
		panic("[Error] while wiping the `CACHE` table")
	}

	_, err = w_policy_stmt.Exec(pol)
	if err != nil {
		panic("[Error] while wiping the `POLICY` table")
	}

	_, err = w_rule_stmt.Exec(pol)
	if err != nil {
		panic("[Error] while wiping the `RULE` table")
	}

	_, err = w_deny_stmt.Exec(pol)
	if err != nil {
		panic("[Error] while wiping the `DENY` table")
	}

	fmt.Printf("[*] Entries related to %s wiped out\n", command)
}

// Sets the permission associated to all the requirements matching
// `req_regex` for `pol` to `perm`. `req_regex` is SQL like pattern.
func UpdateRequirementPermission(pol int, req_regex string, perm int) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the update statement
	update_query := `UPDATE RULE SET perm = ? ` +
		`WHERE pol == ? AND req LIKE ?;`
	update_stmt, err := profiles_db.Prepare(update_query)
	if err != nil {
		panic("[Error] while preparing the update statement")
	}

	// remove the values
	fmt.Println(pol, req_regex, perm)
	_, err = update_stmt.Exec(perm, pol, req_regex)
	if err != nil {
		panic("[Error] during requirement update")
	}

	// post processing
	ruleTablePostProcessing(profiles_db, pol)

	fmt.Printf("[*] List of requirements of pol %d updated\n", pol)
}

// Wipes out the profiles-DB.
func WipeProfiles() {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statements
	wipe_cache := `DELETE FROM CACHE;`
	wipe_policy := `DELETE FROM POLICY;`
	wipe_rule := `DELETE FROM RULE;`
	wipe_deny := `DELETE FROM DENY;`

	w_cache_stmt, err := profiles_db.Prepare(wipe_cache)
	if err != nil {
		panic("[Error] while preparing the wipe cache statement")
	}

	w_policy_stmt, err := profiles_db.Prepare(wipe_policy)
	if err != nil {
		panic("[Error] while preparing the wipe policy statement")
	}

	w_rule_stmt, err := profiles_db.Prepare(wipe_rule)
	if err != nil {
		panic("[Error] while preparing the wipe rule statement")
	}

	w_deny_stmt, err := profiles_db.Prepare(wipe_deny)
	if err != nil {
		panic("[Error] while preparing the wipe deny statement")
	}

	// remove the values
	_, err = w_cache_stmt.Exec()
	if err != nil {
		panic("[Error] while wiping the `CACHE` table")
	}

	_, err = w_policy_stmt.Exec()
	if err != nil {
		panic("[Error] while wiping the `POLICY` table")
	}

	_, err = w_rule_stmt.Exec()
	if err != nil {
		panic("[Error] while wiping the `RULE` table")
	}

	_, err = w_deny_stmt.Exec()
	if err != nil {
		panic("[Error] while wiping the `DENY` table")
	}

	fmt.Println("[*] Profiles-DB wiped out")
}

// Returns all the requirements associated to a policy
func GetCommandRequirements(pol int) []PolicyRow {
	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	select_query := `SELECT req, perm, origin FROM RULE WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// put the result into a slice of PolicyRow
	var requirements []PolicyRow
	var requirement PolicyRow

	for res.Next() {
		requirement = PolicyRow{}
		var perm int
		res.Scan(&requirement.Req, &perm, &requirement.Origin)
		requirement.Perm = *IntToPermission(perm)
		requirements = append(requirements, requirement)
	}

	return requirements
}

// Wipes the security profile of a policy
func WipeSecurityProfile(pol int) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the wipe statement
	wipe_query := `DELETE FROM PROFILE ` +
		`WHERE pol == ?;`
	wipe_stmt, err := profiles_db.Prepare(wipe_query)
	if err != nil {
		panic("[Error] while preparing the wipe security profile statement")
	}

	// remove the values
	_, err = wipe_stmt.Exec(pol)
	if err != nil {
		panic("[Error] during profile wipe")
	}
	if DEBUG_SERIALIZER {
		fmt.Printf("[*] Old security profile of policy %d wiped out from profiles-DB\n", pol)
	}
}

// Creates the security profile for a policy.
func CreateSecurityProfile(pol int, policy *[]PolicyRow) {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the create statement
	create_query := `INSERT INTO PROFILE(` +
		`pol, req, perm) VALUES (?,?,?);`
	create_stmt, err := profiles_db.Prepare(create_query)
	if err != nil {
		panic("[Error] while preparing the create statement")
	}

	// create the security profile
	for _, row := range *policy {
		_, err = create_stmt.Exec(pol,
			row.Req,
			row.Perm.ToUnixInt())
		if err != nil {
			panic("[Error] during create security profile")
		}
	}
	if DEBUG_SERIALIZER {
		fmt.Printf("[*] New security profile for policy %d created in profiles-DB\n", pol)
	}
}

// Returns the security profile of a command
func GetSecurityProfile(pol int) []PolicyRow {

	// get a reference to the DB
	profiles_db, err := sql.Open("sqlite3", DB_NAME)
	defer profiles_db.Close()
	if err != nil {
		panic("Couldn't open `" + DB_NAME + "`")
	}

	// prepare the delete statement
	select_query := `SELECT req, perm FROM PROFILE WHERE pol == ?;`
	select_stmt, err := profiles_db.Prepare(select_query)
	if err != nil {
		panic("[Error] while preparing the select statement")
	}

	// get the values
	res, err := select_stmt.Query(pol)
	if err != nil {
		panic(err)
	}
	defer res.Close()

	// put the result into a slice of PolicyRow
	var requirements []PolicyRow
	var requirement PolicyRow

	for res.Next() {
		requirement = PolicyRow{}
		var perm int
		res.Scan(&requirement.Req, &perm)
		requirement.Perm = *IntToPermission(perm)
		requirements = append(requirements, requirement)
	}

	return requirements
}
