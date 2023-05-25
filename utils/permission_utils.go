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
	"os"
	"strings"
)

// Permissions associated with a requirement
type Permission struct {
	X bool
	W bool
	R bool
}

// Gets a permission string and returns a `Permission` instance
func InitPermission(perm string) *Permission {
	var p Permission
	if len(perm) != 3 {
		panic("Invalid permission found")
	}

	perm = strings.ToLower(perm)

	if perm[0] == 'r' {
		p.R = true
	} else if perm[0] != '-' {
		panic("Invalid permission found")
	}

	if perm[1] == 'w' {
		p.W = true
	} else if perm[1] != '-' {
		panic("Invalid permission found")
	}

	if perm[2] == 'x' {
		p.X = true
	} else if perm[2] != '-' {
		panic("Invalid permission found")
	}

	return &p
}

// Converts an integer permission to a Permission
func IntToPermission(perm int) *Permission {

	p := Permission{}

	if perm-4 >= 0 {
		p.R = true
		perm -= 4
	}
	if perm-2 >= 0 {
		p.W = true
		perm -= 2
	}
	if perm-1 == 0 {
		p.X = true
	}

	return &p
}

func (perm *Permission) IsExecutable() bool {
	return perm.X
}

func (perm *Permission) IsWritable() bool {
	return perm.W
}

func (perm *Permission) IsReadable() bool {
	return perm.R
}

func (perm *Permission) ToUnixInt() uint8 {
	var m = map[bool]uint8{true: 1, false: 0}
	return m[perm.R]*4 + m[perm.W]*2 + m[perm.X]
}

func (perm *Permission) ToUnixBitString() string {
	var m = map[bool]string{true: "1", false: "0"}
	return m[perm.R] + m[perm.W] + m[perm.X]
}

func (perm *Permission) ToString() string {
	var p string
	if perm.IsReadable() {
		p += "R"
	} else {
		p += "-"
	}
	if perm.IsWritable() {
		p += "W"
	} else {
		p += "-"
	}
	if perm.IsExecutable() {
		p += "X"
	} else {
		p += "-"
	}

	return p
}

func (perm *Permission) ToStringSlice() []string {

	p := make([]string, 3)

	if perm.IsReadable() {
		p[0] = "R"
	} else {
		p[0] = "-"
	}
	if perm.IsWritable() {
		p[1] = "W"
	} else {
		p[1] = "-"
	}
	if perm.IsExecutable() {
		p[2] = "X"
	} else {
		p[2] = "-"
	}

	return p
}

// Returns true if the integer permission `perm` matches mask m
func (perm *Permission) PermissionMatch(mask string) bool {

	if len(mask) != 3 {
		panic("[Error] invalid permission mask provided")
	}

	match := make(map[byte]bool)

	match['r'] = true
	match['w'] = true
	match['x'] = true
	match['-'] = false

	if mask[0] != '_' {
		if match[mask[0]] != perm.R {
			return false
		}
	}
	if mask[1] != '_' {
		if match[mask[1]] != perm.W {
			return false
		}
	}
	if mask[2] != '_' {
		if match[mask[2]] != perm.X {
			return false
		}
	}

	return true
}

func (perm *Permission) ToUnixString() string {
	var pstr string

	if perm.R {
		pstr += "R"
	} else {
		pstr += "-"
	}
	if perm.W {
		pstr += "W"
	} else {
		pstr += "-"
	}
	if perm.X {
		pstr += "X"
	} else {
		pstr += "-"
	}

	return pstr
}

// Returns `true` if the permission input by the user is valid
func IsValidPerm(perm string) bool {

	if len(perm) != 3 {
		return false
	}

	if perm[0] != 'r' && perm[0] != '-' {
		return false
	}
	if perm[1] != 'w' && perm[1] != '-' {
		return false
	}
	if perm[2] != 'x' && perm[2] != '-' {
		return false
	}

	return true
}

// Returns `true` if the permission mask input by the user is
// valid. Each bit in the mask can be set to `_` (don't care), `-`
// (false), and `B` (true); where `B` in {`r`;`w`;`x`} based on the
// bitmask position.
func IsValidMask(mask string) bool {

	if len(mask) != 3 {
		return false
	}

	if mask[0] != 'r' && mask[0] != '_' && mask[0] != '-' {
		return false
	}
	if mask[1] != 'w' && mask[1] != '_' && mask[1] != '-' {
		return false
	}
	if mask[2] != 'x' && mask[2] != '_' && mask[2] != '-' {
		return false
	}

	return true
}

// Returns `true` if the requirement `path` input by the user exists
func IsValidRequirement(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}
