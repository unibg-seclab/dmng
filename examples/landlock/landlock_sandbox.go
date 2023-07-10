package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func execMem(procName string, elfPath string) {

}

// This program supports Landlock ABI version >= 2, please upgrade otherwise
var LANDLOCK_ABI_VERSION int

var llPermissions = map[string]ll.AccessFSSet{
	"execute":     llsys.AccessFSExecute,
	"write_file":  llsys.AccessFSWriteFile,
	"read_file":   llsys.AccessFSReadFile,
	"read_dir":    llsys.AccessFSReadDir,
	"remove_dir":  llsys.AccessFSRemoveDir,
	"remove_file": llsys.AccessFSRemoveFile,
	"make_char":   llsys.AccessFSMakeChar,
	"make_dir":    llsys.AccessFSMakeDir,
	"make_reg":    llsys.AccessFSMakeReg,
	"make_sock":   llsys.AccessFSMakeSock,
	"make_fifo":   llsys.AccessFSMakeFifo,
	"make_block":  llsys.AccessFSMakeBlock,
	"make_sym":    llsys.AccessFSMakeSym,
	"refer":       llsys.AccessFSRefer,
	"truncate":    llsys.AccessFSTruncate,
}

func main() {

	LANDLOCK_ABI_VERSION, err := llsys.LandlockGetABIVersion()
	check(err)
	fmt.Printf("%s%d\n", "Sandboxing component with Landlock ABI V", LANDLOCK_ABI_VERSION)

	f1 := "../file1.txt" // read
	f2 := "../file2.txt" // no permissions
	fw := "/dev/stdout"  // read/write
	fx := "../prog.out"  // read/exec

	read_recover_msg := "recovering from attempted read of file"
	write_recover_msg := "recovering from attempted write to file"

	if err := ll.MustConfig(accessAllSet()).RestrictPaths(
		ll.PathAccess(accessFileReadSet(), f1),
		ll.PathAccess(accessFileWriteSet()|accessFileReadSet(), fw),
		ll.PathAccess(accessFileReadSet(), "/etc/ld.so.cache"),
		ll.PathAccess(accessFileReadSet(), "/lib/x86_64-linux-gnu/libc.so.6"),
		ll.PathAccess(accessFileReadSet(), "/lib64/ld-linux-x86-64.so.2"),
		ll.PathAccess(accessFileReadSet()|accessFileExecSet(), "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
		ll.PathAccess(accessFileReadSet()|accessFileExecSet(), fx),
	); err != nil {
		log.Fatalf("Cannot restrict paths: %v", err)
	}

	// granted read
	test_wrapper(file_read, f1, read_recover_msg)
	// denied read
	test_wrapper(file_read, f2, read_recover_msg)
	// granted write
	test_wrapper(file_write, fw, write_recover_msg)
	// denied write
	test_wrapper(file_write, f1, write_recover_msg)
	// successful exec
	test_wrapper(file_exec, fx, "")

}

func test_wrapper(f func(string), filepath, msg string) {
	defer func() {
		err := recover()
		if err != nil {
			fmt.Println(err)
			fmt.Printf("-> %s %s\n", msg, filepath)

		}
		fmt.Println("---")
	}()
	f(filepath)
}

func file_read(filepath string) {
	f, err := os.Open(filepath)
	if err != nil {
		panic(fmt.Sprintf("Unable to open from file %v", filepath))
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("Unable to read content of file %s", filepath)
	}
	fmt.Print(string(content))

}

func file_write(filepath string) {

	msg := []byte("landlock write test\n")

	err := os.WriteFile(filepath, msg, 0644)
	if err != nil {
		panic(fmt.Sprintf("Unable to write or create file %s, error %v", filepath, err))
	} else {
		fmt.Printf("Successfully written to %s\n", filepath)
	}
}

func file_exec(filepath string) {

	identity, _, _ := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)

	// child inherits parent policy

	if identity != 0 {
		fmt.Printf("Trying to exec %s: ", filepath)
		time.Sleep(500 * time.Millisecond)
	} else {
		// create anonymous fd
		fdName := ""
		const memfdCreate = 319
		const mfdCloExec = 0x0001
		fd, _, _ := syscall.Syscall(memfdCreate, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloExec), 0)

		// write program to fd
		buf, _ := ioutil.ReadFile(filepath)
		_, _ = syscall.Write(int(fd), buf)

		// exec
		fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
		_ = syscall.Exec(fdPath, []string{"demo program"}, nil)
	}
}

func accessFileReadSet() (as ll.AccessFSSet) {
	perms := []string{"read_file"}
	for _, p := range perms {
		a, ok := llPermissions[p]
		if !ok {
			log.Fatalf("Unknown acces permission %s", p)
		}
		as |= a
	}
	return as
}

func accessFileWriteSet() (as ll.AccessFSSet) {
	perms := []string{"write_file", "refer", "truncate"}
	for _, p := range perms {
		if (p == "truncate" || p == "refer") && LANDLOCK_ABI_VERSION < 3 {
			continue
		}
		a, ok := llPermissions[p]
		if !ok {
			log.Fatalf("Unknown acces permission %s", p)
		}
		as |= a
	}
	return as
}

func accessFileExecSet() (as ll.AccessFSSet) {
	perms := []string{"execute"}
	for _, p := range perms {
		a, ok := llPermissions[p]
		if !ok {
			log.Fatalf("Unknown acces permission %s", p)
		}
		as |= a
	}
	return as
}

func accessDirReadSet() (as ll.AccessFSSet) {
	perms := []string{"read_dir"}
	for _, p := range perms {
		a, ok := llPermissions[p]
		if !ok {
			log.Fatalf("Unknown acces permission %s", p)
		}
		as |= a
	}
	return as
}

func accessDirWriteSet() (as ll.AccessFSSet) {
	perms := []string{
		"remove_dir",
		"remove_file",
		"make_char",
		"make_dir",
		"make_reg",
		"make_sock",
		"make_fifo",
		"make_block",
		"make_sym",
	}
	for _, p := range perms {
		a, ok := llPermissions[p]
		if !ok {
			log.Fatalf("Unknown acces permission %s", p)
		}
		as |= a
	}
	return as
}

func accessAllSet() (as ll.AccessFSSet) {
	for k, v := range llPermissions {
		if (k == "truncate" || k == "refer") && LANDLOCK_ABI_VERSION < 3 {
			continue
		}
		as |= v
	}
	return as
}
