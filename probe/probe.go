// The containment self-test's probe (selftest.py): hostile and calibration
// behaviours the executor runs inside its own jails, `probe <name> [arg]`.
// Static, so a jail needs nothing mounted but this binary.
//
// judgebox's internal/probe/probe.go, re-checked when judgebox changes it.
// Differences: a standalone main; the workspace is /code, not /box;
// default_deny no longer tries getcpu, which our policies allow (the JVM's
// sched_getcpu makes the real syscall under gVisor); ioctl_highbits uses a
// pipe; noop can idle so its memory gets polled; and `syscall` makes any
// raw syscall, for the rest of the kill set.
//
// Convention: exit 0 = the containment held (the attempt failed the way it
// should). Exit 1 = containment broken. Some probes are expected to be killed
// instead (memory, cpu, ptrace); the executor checks the jail's result for those.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "noop":
		var ru syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		// Our own footprint, so the engine can subtract only the sandbox's.
		fmt.Printf("%d %d\n", ru.Maxrss<<10, ru.Utime.Nano()+ru.Stime.Nano())
		// Then idle for arg ms: gVisor has no memory peak counter, so the
		// executor only sees the jail's memory by polling it while it runs.
		ms, _ := strconv.Atoi(arg(args, 1))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return 0
	case "alloc":
		mb, _ := strconv.Atoi(arg(args, 1))
		bufs := make([][]byte, 0, mb)
		for i := 0; i < mb; i++ {
			b := make([]byte, 1<<20)
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			bufs = append(bufs, b)
		}
		runtime.KeepAlive(bufs)
		return 1
	case "spin":
		x := 0
		for {
			x++
		}
	case "sleep":
		time.Sleep(time.Hour)
		return 1
	case "threads":
		n, _ := strconv.Atoi(arg(args, 1))
		started := make(chan struct{})
		for i := 0; i < n; i++ {
			go func() {
				runtime.LockOSThread() // forces one OS thread per goroutine
				started <- struct{}{}
				select {}
			}()
			<-started
		}
		return 1 // all threads created: pids limit not enforced
	case "fork":
		pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
		if errno != 0 {
			return 0
		}
		if pid == 0 {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
		}
		return 1
	case "socket":
		for _, fam := range []int{syscall.AF_INET, syscall.AF_INET6, syscall.AF_UNIX, syscall.AF_NETLINK, syscall.AF_PACKET} {
			if fd, err := syscall.Socket(fam, syscall.SOCK_STREAM, 0); err == nil {
				syscall.Close(fd)
				fmt.Printf("socket family %d allowed\n", fam)
				return 1
			}
		}
		return 0
	case "ptrace":
		syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_TRACEME, 0, 0)
		return 1 // should have been killed
	case "syscall":
		// `syscall <nr> [arg...]`: a raw syscall the policy must kill. Not in
		// judgebox, which tries only ptrace and unshare.
		var a [6]uintptr
		nr, _ := strconv.ParseUint(arg(args, 1), 0, 64)
		for i := range a {
			v, _ := strconv.ParseUint(arg(args, i+2), 0, 64)
			a[i] = uintptr(v)
		}
		syscall.RawSyscall6(uintptr(nr), a[0], a[1], a[2], a[3], a[4], a[5])
		return 1 // should have been killed
	case "unshare":
		syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER, 0, 0)
		return 1
	case "x32":
		// getpid via the x32 ABI bit; an arch check alone would miss this.
		r, _, errno := syscall.RawSyscall(0x40000000|syscall.SYS_GETPID, 0, 0, 0)
		if errno != 0 {
			return 0
		}
		fmt.Printf("x32 getpid returned %d\n", r)
		return 1
	case "io_uring":
		var params [120]byte
		_, _, errno := syscall.RawSyscall(425 /* io_uring_setup */, 8, uintptr(unsafe.Pointer(&params[0])), 0)
		if errno != 0 {
			return 0
		}
		return 1
	case "ioctl_highbits":
		// The kernel truncates ioctl's cmd to 32 bits, so 0x1_0000541B
		// executes FIONREAD. A seccomp check that compares only the low 32
		// bits (or a denylist) lets it through; ours must compare all 64.
		// FIONREAD on a pipe succeeds, so a pass is observable. (judgebox uses
		// a regular file in /tmp, which gVisor's tmpfs answers with ENOTTY.)
		var fds [2]int
		if err := syscall.Pipe(fds[:]); err != nil {
			fmt.Printf("inconclusive: %v\n", err)
			return 3
		}
		syscall.Write(fds[1], []byte("12345"))
		f := os.NewFile(uintptr(fds[0]), "pipe")
		var n int32
		if _, _, e := syscall.RawSyscall(syscall.SYS_IOCTL, f.Fd(), 0x541B, uintptr(unsafe.Pointer(&n))); e != 0 {
			fmt.Printf("inconclusive: plain FIONREAD failed: %v\n", e)
			return 3 // control failed: the test can't conclude anything
		}
		if _, _, e := syscall.RawSyscall(syscall.SYS_IOCTL, f.Fd(), 0x1_0000541B, uintptr(unsafe.Pointer(&n))); e == 0 {
			fmt.Println("high-bit ioctl request was executed")
			return 1
		}
		return 0
	case "fs":
		bad := 0
		for _, p := range []string{"/etc/shadow", "/proc/self/status", "/sys/kernel", "/root", "/var/run/docker.sock", "/run"} {
			if _, err := os.Stat(p); err == nil {
				fmt.Printf("visible: %s\n", p)
				bad++
			}
		}
		for _, p := range []string{"/code/x", "/x", "/etc/x", "/dev/x"} {
			err := os.WriteFile(p, []byte("x"), 0o644)
			if p == "/code/x" && arg(args, 1) == "compile" {
				// The compile phase must be able to write its output to /code.
				if err != nil {
					fmt.Printf("/code not writable in compile phase: %v\n", err)
					bad++
				}
				continue
			}
			if err == nil {
				fmt.Printf("writable: %s\n", p)
				bad++
			}
		}
		if err := os.WriteFile("/tmp/ok", []byte("x"), 0o644); err != nil {
			fmt.Printf("/tmp not writable: %v\n", err)
			bad++
		}
		if os.Getuid() == 0 || os.Geteuid() == 0 {
			fmt.Println("running as root inside the sandbox")
			bad++
		}
		if bad > 0 {
			return 1
		}
		return 0
	case "default_deny":
		// Syscalls the policy never mentions must hit the DEFAULT action.
		// Every other probe targets an explicitly listed syscall, so without
		// this one a policy whose default was ALLOW would pass the self-test.
		// These are harmless and succeed on a normal kernel.
		name := []byte("probe\x00")
		calls := []struct {
			name string
			nr   uintptr
			a    [3]uintptr
		}{
			{"memfd_create", 319, [3]uintptr{uintptr(unsafe.Pointer(&name[0])), 0, 0}},
			{"inotify_init1", syscall.SYS_INOTIFY_INIT1, [3]uintptr{0, 0, 0}},
		}
		leaked := 0
		for _, c := range calls {
			r, _, e := syscall.RawSyscall(c.nr, c.a[0], c.a[1], c.a[2])
			if e == 0 {
				fmt.Printf("unlisted syscall %s was allowed\n", c.name)
				leaked++
				syscall.Close(int(r))
			}
		}
		if leaked > 0 {
			return 1
		}
		return 0
	case "caps":
		// CapEff must be zero; read via capget (no /proc available).
		hdr := [2]uint32{0x20080522, 0}
		var data [6]uint32
		syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)), 0)
		if data[0]|data[3] != 0 { // effective low|high words
			fmt.Printf("effective capabilities: %x %x\n", data[3], data[0])
			return 1
		}
		return 0
	case "forkbomb":
		// Compile phase allows fork; pids.max + RLIMIT_NPROC must bound it.
		// Children only sleep (raw syscalls, no Go runtime use after fork).
		n, _ := strconv.Atoi(arg(args, 1))
		ts := syscall.Timespec{Sec: 60}
		created := 0
		for ; created < n; created++ {
			pid, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
			if errno != 0 {
				break
			}
			if pid == 0 {
				for {
					syscall.RawSyscall(syscall.SYS_NANOSLEEP, uintptr(unsafe.Pointer(&ts)), 0, 0)
				}
			}
		}
		fmt.Printf("%d\n", created)
		if created >= n {
			return 1 // never hit a limit
		}
		return 0
	case "flood":
		n, _ := strconv.Atoi(arg(args, 1))
		chunk := make([]byte, 1<<20)
		for i := 0; i < n; i++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 0
			}
		}
		return 1
	}
	return 2
}

func arg(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}
