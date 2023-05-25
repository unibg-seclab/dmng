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
	"bytes"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

type Node struct {
	name         string           // node name (e.g., "libc.so")
	path         string           // absolute path (e.g., "/usr/bin/libc.so")
	perm         Permission       // the permission given to the current path (e.g., `rw-`)
	origin       string           // origin of the requirement (e.g., `USER_INPUT_FILE`) [for leaves only]
	permissioned bool             // indicates whether the current node has a permission attached
	connections  map[string]*Node // connections to from this fs dir [`name`] -> `Node`
}

// allow coarse read paths
var ALLOW_COARSE_READ = map[string]bool{
	"/bin":       true,
	"/lib":       true,
	"/lib32":     true,
	"/lib64":     true,
	"/libx32":    true,
	"/sbin":      true,
	"/opt":       true,
	"/usr":       true,
	"/etc/fonts": true,
}

// allow coarse write paths
var ALLOW_COARSE_WRITE = map[string]bool{
	"/dev": true,
	"/var": true,
	"/sys": true,
}

// ignored paths
var IGNORED_PATHS = map[string]bool{
	"/proc": true,
}

// truncate utils debug flag
var DEBUG_TRUNCATE bool = false

// Creates the Trie of a command out of a slice of `requirements`
// PolicyRows.
func CreateTrie(command string, requirements []PolicyRow) *Node {

	user, err := user.Current()
	checkErr(err)

	// augmenting allow paths
	ALLOW_COARSE_READ["/home/"+user.Username+"/.local/share"] = true
	ALLOW_COARSE_READ["/home/"+user.Username+"/.cache/fontconfig"] = true
	ALLOW_COARSE_WRITE["/home/"+user.Username+"/.cache/"+command] = true
	ALLOW_COARSE_WRITE["/home/"+user.Username+"/.config/"+command] = true
	ALLOW_COARSE_WRITE["/tmp/"+command] = true
	ALLOW_COARSE_WRITE["/tmp/"] = true

	var trie *Node = createTrieNode("/", "", Permission{}, "", false)

	for _, requirement := range requirements {
		// req, perm, origin
		trie.addRequirement(requirement.Req, requirement.Perm,
			requirement.Origin)
	}

	return trie
}

// Creates a new Node with given a parameter set. It initializes an
// empty map of `connections`
func createTrieNode(name, path string, perm Permission, origin string, permissioned bool) *Node {

	var n Node

	n.name = name
	n.path = path
	n.perm = perm
	n.origin = origin
	n.permissioned = permissioned
	n.connections = make(map[string]*Node)

	return &n
}

// Adds a requirement (`req`, `perm`, `origin`) to a command Trie. Use
// only absolute paths for requirements
func (root *Node) addRequirement(req string, perm Permission, origin string) {

	// ignored paths aren't something we may want to restrict, so
	// we don't add them to the Trie
	for ignp := range IGNORED_PATHS {
		if strings.HasPrefix(req, ignp) {
			return
		}
	}

	// get all the elements inside the path
	names := strings.Split(req, "/")
	// strip the leading empty string if present
	if len(names) > 1 {
		if names[0] == "" {
			names = names[1:]
		}
	}
	// get the name of the child whose attributes (perm, origin) need to be updated
	var last_name string
	if len(names) > 0 {
		last_name = names[len(names)-1]
	}

	incremental_path := root.path
	currnode := root
	// for each subpath element
	for _, name := range names {
		// check Trie insertion
		if child, ok := currnode.connections[name]; ok { // subpath present
			if last_name == name { // update permission of the current node
				child.perm = perm
				child.permissioned = true
				child.origin = origin
			}
			incremental_path = child.path
			currnode = child
		} else { // insertion
			incremental_path = incremental_path + "/" + name
			currnode.connections[name] = createTrieNode(name,
				incremental_path,
				Permission{},
				"",
				false)
			if name == last_name {
				currnode.connections[name].perm = perm
				currnode.connections[name].origin = origin
				currnode.connections[name].permissioned = true
			}
			currnode = currnode.connections[name]
		}

	}
}

// Prints the Trie to a bytes.Buffer
func (root *Node) PrintTrie(buffer *bytes.Buffer, depth int) {
	var formatter string
	if depth != 0 {
		formatter = strconv.Itoa(depth) + "|__"
	}
	buffer.WriteString(strings.Repeat("  ", depth) + formatter)
	root.printNode(buffer)
	for _, node := range root.connections {
		node.PrintTrie(buffer, depth+1)
	}
}

// Prints a `Node` to a bytes.Buffer `buffer`
func (n *Node) printNode(buffer *bytes.Buffer) {

	var formatter string

	if n.permissioned {
		formatter = " ["
	}

	buffer.WriteString(n.path + formatter)

	if n.origin != "" {
		formatter = "] ["
	}

	if n.permissioned {
		buffer.WriteString(n.perm.ToString() + formatter)
	}

	if n.origin == "" {
		formatter = "\n"
	} else {
		formatter = "]\n"
	}

	buffer.WriteString(n.origin + formatter)
}

// Prunes the Trie until it contains a number of permissioned nodes
// (the ones with `permissioned` = true) less or equal than `goal`
func (root *Node) PruneTrie(goal int) bool {

	// guard
	if goal <= 0 {
		panic("Invalid pruning goal")
	}

	// check no need to prune
	if counter := root.CountPermissionedNodes(); goal >= counter {
		if DEBUG_TRUNCATE {
			fmt.Printf("[D] No need to prune (Nof permission found: %d, Goal: %d)\n", counter, goal)
		}
		return true
	}

	if root.PruneRX(goal) || root.PruneRW(goal) {
		if DEBUG_TRUNCATE {
			// get the number of permissioned nodes
			counter := root.CountPermissionedNodes()
			fmt.Printf("[D] Nof permissioned nodes after pruning: %d\n", counter)
		}
		return true
	}

	return false

}

func (root *Node) PruneRX(goal int) bool {

	// if node belongs to ALLOW_COARSE_READ paths, we can "safely"
	// reduce the number of permissions using less fine-grained
	// paths. The rationale is that a program may need to access
	// those system areas for example to load dependencies and
	// default settings. `RW` permissions are instead preserved
	// (we grant the permission to modify the fs only if it is
	// required to run the command successfully).
	for _, node := range root.connections {
		if isAllowCoarseRead(node.path) {
			if DEBUG_TRUNCATE {
				fmt.Printf("[D] Attempting to prune (`ALLOW_READ`): %s\n", node.path)
			}
			node._pruneRX(goal) // prune the branch originating from node
		} else if isAllowCoarseReadPrefix(node.path) {
			node.PruneRX(goal) // look for other branches to prune
		}
	}

	if counter := root.CountPermissionedNodes(); counter <= goal {
		return true
	}

	return false
}

func (root *Node) PruneRW(goal int) bool {

	// as the last chance to achieve the pruning goal, we can
	// reduce the number of `RW` permissioned paths. Take the path
	// `/dev` as an example, the rationale is that we don't want
	// Landlock to stop a program using the resources located
	// there (we expect DAC to be the primary sandboxing mechanism
	// for that portion of the filesystem)
	for _, node := range root.connections {
		if isAllowCoarseWrite(node.path) {
			if DEBUG_TRUNCATE {
				fmt.Printf("[D] Attempting to prune (`ALLOW_WRITE`): %s\n", node.path)
			}
			node._pruneRW(goal)
		} else if isAllowCoarseWritePrefix(node.path) {
			node.PruneRW(goal)
		}
	}

	if counter := root.CountPermissionedNodes(); counter <= goal {
		return true
	}

	return false
}

// Returns `true` if `path` belong to the ALLOW_COARSE_READ
func isAllowCoarseRead(path string) bool {
	if _, ok := ALLOW_COARSE_READ[path]; ok {
		return true
	}
	return false

}

// Returns `true` if `path` is a valid ALLOW_COARSE_READ prefix
func isAllowCoarseReadPrefix(path string) bool {
	for p := range ALLOW_COARSE_READ {
		if strings.HasPrefix(p, path) {
			return true
		}
	}
	return false
}

// Returns `true` if `path` belong to the ALLOW_COARSE_WRITE
func isAllowCoarseWrite(path string) bool {
	if _, ok := ALLOW_COARSE_WRITE[path]; ok {
		return true
	}
	return false

}

// Returns `true` if `path` is a valid ALLOW_COARSE_WRITE prefix
func isAllowCoarseWritePrefix(path string) bool {
	for p := range ALLOW_COARSE_WRITE {
		if strings.HasPrefix(p, path) {
			return true
		}
	}
	return false
}

// Applies pruning to the Trie rooted in `root` reducing the number of
// permissioned nodes.
func (root *Node) _pruneRX(goal int) {

	// cannot prune a leaf node
	if len(root.connections) == 0 {
		return
	} else {
		// prune `root.connections`
		for _, node := range root.connections {
			if !node.isLeaf() {
				node._pruneRX(goal)
			}
		}
		// prune `root`
		if DEBUG_TRUNCATE {
			fmt.Printf("[D] Current root: %s\n", root.path)
		}
		// retrieve RX connections
		rx_nodes := make(map[string]*Node)
		other_nodes := make(map[string]*Node)
		for name, node := range root.connections {
			if len(node.connections) != 0 {
				other_nodes[name] = node
			} else if node.perm.PermissionMatch("_-_") {
				rx_nodes[name] = node
			}
		}
		if DEBUG_TRUNCATE {
			fmt.Printf("[D] root rx_nodes: %v\n", rx_nodes)
		}
		// truncate only if assigning RX to root makes sense
		if len(rx_nodes) <= 1 {
			return
		} else {
			// watermark `rx_nodes` permissionsp
			hasR := false
			hasX := false
			for _, tn := range rx_nodes {
				if tn.perm.IsReadable() {
					hasR = true
				}
				if tn.perm.IsExecutable() {
					hasX = true
				}
				if hasR && hasX {
					break
				}
			}
			// assign permissions to `root`
			root.perm.R = hasR
			root.perm.X = hasX
			root.permissioned = true
			root.origin = PRUNING_RX
			// remove all `rx_nodes` found previously
			for name := range rx_nodes {
				delete(root.connections, name)
			}

			if DEBUG_TRUNCATE {
				fmt.Printf("[D] Pruned %d permissioned nodes\n", len(rx_nodes)-1)
			}
			return
		}
	} // end pruning
}

func (root *Node) _pruneRW(goal int) {

	// cannot prune a leaf node
	if len(root.connections) == 0 {
		return
	} else {
		// prune `root.connections`
		for _, node := range root.connections {
			if !node.isLeaf() {
				node._pruneRW(goal)
			}
		}
		// prune `root`
		if DEBUG_TRUNCATE {
			fmt.Printf("[D] Current root: %s\n", root.path)
		}
		// determine least privilege

		// retrieve connections
		rn_nodes := make(map[string]*Node)
		rw_nodes := make(map[string]*Node)
		for name, node := range root.connections {
			if node.perm.PermissionMatch("r-_") {
				if len(node.connections) == 0 {
					rn_nodes[name] = node
				}
			} else if node.perm.PermissionMatch("rw-") {
				if len(node.connections) == 0 {
					rw_nodes[name] = node
				}
			}

		}
		if DEBUG_TRUNCATE {
			fmt.Printf("[D] root rn_nodes: %v\n", rn_nodes)
			fmt.Printf("[D] root rw_nodes: %v\n", rw_nodes)
		}

		if len(rn_nodes)+len(rw_nodes) <= 1 {
			if len(rw_nodes) == 0 {
				for _, nt := range rn_nodes {
					root.perm = nt.perm
				}
				// assign permission to root
				root.permissioned = true
				root.origin = PRUNING_RW
				// delete the single ro_node
				for name := range rn_nodes {
					delete(root.connections, name)
				}
				// no need to update the counter (1 permission removed and 1 added)
			}
			return
		} else {
			// watermark `rn_nodes` permissionsp
			hasR := false
			hasX := false
			for _, tn := range rn_nodes {
				if tn.perm.IsReadable() {
					hasR = true
				}
				if tn.perm.IsExecutable() {
					hasX = true
				}
				if hasR && hasX {
					break
				}
			}
			// assign permissions to `root`
			root.perm.R = hasR
			root.perm.X = hasX
			root.perm.W = true
			root.permissioned = true
			root.origin = PRUNING_RW
			// remove all `ro_nodes` and `rw_nodes` found previously
			for name := range rn_nodes {
				delete(root.connections, name)
			}
			for name := range rw_nodes {
				delete(root.connections, name)
			}

			if DEBUG_TRUNCATE {
				fmt.Printf("[D] Pruned %d permissioned nodes\n", len(rn_nodes)+len(rw_nodes)-1)
			}

			return
		}
	} // end pruning
}

// Counts the number of nodes in the Trie associated with a permission
func (root *Node) CountPermissionedNodes() int {
	counter := 0
	for _, child := range root.connections {
		counter += child.CountPermissionedNodes()
	}
	if root.permissioned {
		counter += 1
	}
	return counter
}

// Returns `true` if a node is a leaf
func (root *Node) isLeaf() bool {
	if len(root.connections) == 0 {
		return true
	}
	return false
}

// Reads the security profile from a Trie after pruning was
// applied. Stores the entries into `result`.
func (root *Node) GetSecurityProfile(profile *[]PolicyRow) {

	if root.permissioned {
		var entry PolicyRow
		entry.Req = root.path
		entry.Perm = root.perm
		entry.Origin = root.origin
		*profile = append(*profile, entry)
	}
	for _, node := range root.connections {
		node.GetSecurityProfile(profile)
	}
}

// Prints all the permissioned nodes in the Trie
func (root *Node) PrintTrieProfile(buffer *bytes.Buffer) {

	if root.permissioned {
		buffer.WriteString("    " + root.path + " [")
		buffer.WriteString(root.perm.ToString() + "] [")
		buffer.WriteString(root.origin + "]\n")
	}
	for _, node := range root.connections {
		node.PrintTrieProfile(buffer)
	}
}
