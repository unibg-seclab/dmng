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
	"encoding/json"
	"io"
	"os"
	"strings"
)

// serializer debug flag
var DEBUG_SERIALIZER bool = false

type CmdPolicy struct {
	Policy_name string   `json:"policy_name"`
	Read        []string `json:"read"`
	Write       []string `json:"write"`
	Exec        []string `json:"exec"`
	Deny        []string `json:"deny"`
}

// struct storing all the policies to be serialized
type Policy struct {
	Policies  []CmdPolicy `json:"policies"`
	Max_depth int         `json:"max_depth"`
}

var P Policy

// policy serialization folder
var POLICY_DIR string

func addCmdPolicy(pid PolicyIdentifier, perms SecurityProfile) *CmdPolicy {

	pol := pid.Pol
	cmd := pid.Cmd
	ctx := pid.Ctx
	denials := GetDenials(pol)

	cmdp := &CmdPolicy{"", []string{}, []string{}, []string{}, []string{}}

	cmdp.Policy_name = cmd + "_" + ctx

	// read, write, exec
	for _, r := range perms.Entries {
		if r.Perm.R {
			cmdp.Read = append(cmdp.Read, r.Req)
		}
		if r.Perm.W {
			cmdp.Write = append(cmdp.Write, r.Req)
		}
		if r.Perm.X {
			cmdp.Exec = append(cmdp.Exec, r.Req)
		}

	}

	// automatically add the policy directory to the list of denials
	policy_dir_denial := PolicyRow{}
	policy_dir_denial.Req = POLICY_DIR
	denials = append(denials, policy_dir_denial)

	// denials
	for _, r := range denials {
		cmdp.Deny = append(cmdp.Deny, r.Req)
	}

	// find the max depth of denials and add it to the policy
	curr_max_depth := maxDenialsDepth(denials)
	if curr_max_depth > P.Max_depth {
		P.Max_depth = curr_max_depth
	}

	return cmdp
}

// Serializes all the policies available into the policyfile
func SerializePolicy(pids []PolicyIdentifier, sps []SecurityProfile, pdir string, fname string) {

	P = Policy{}

	POLICY_DIR = pdir

	// write serialized policy to file
	for i, sp := range sps {
		cmdPolicy := *addCmdPolicy(pids[i], sp)
		cmdPolicy.Policy_name = pids[i].Cmd + "_" + pids[i].Ctx
		P.Policies = append(P.Policies, cmdPolicy)
	}

	writePolicy(pdir, fname)
}

// Writes the policy stored in P to file
func writePolicy(pdir, fname string) {

	P_bytes, err := json.MarshalIndent(P, "", "   ")
	checkErr(err)

	f, err := os.OpenFile(pdir+"/"+fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	checkErr(err)
	defer f.Close()

	writer := bufio.NewWriter(f)
	_, err = f.Write(P_bytes)
	checkErr(err)

	writer.Flush()
}

// Unmarshals a policy into the global var P
func deserializePolicy(pdir, pname string) {

	pfile, err := os.Open(pdir + "/" + pname)
	checkErr(err)
	old_policy, err := io.ReadAll(pfile)
	checkErr(err)

	err = json.Unmarshal(old_policy, &P)
	if err != nil {
		panic("Unable to unmarshal the json policy file")
	}
}

// Updates the content of `max_depth` for a given policy. `pdir` is the
// absolute path of the folder in which the policy is stored, `pname`
// the name of the policy.
func FixDepth(pdir, pname string) {

	// read the json policy into P
	deserializePolicy(pdir, pname)

	// get the real max depth value
	max_d := 0
	for _, p := range P.Policies { // for each policy
		for _, deny := range p.Deny { // for each policy deny
			parts := strings.Split(deny, "/")
			parts = parts[1:]
			if len(parts) > max_d {
				max_d = len(parts)
			}
		}

	}

	// update the max depth value
	P.Max_depth = max_d

	// overwrite the policy to file
	writePolicy(pdir, pname)

}

func maxDenialsDepth(denials []PolicyRow) int {

	if len(denials) == 0 {
		return -1
	}

	maxDepth := 0

	for _, d := range denials {
		parts := strings.Split(d.Req, "/")
		parts = parts[1:]
		if len(parts) > maxDepth {
			maxDepth = len(parts)
		}
	}

	return maxDepth
}
