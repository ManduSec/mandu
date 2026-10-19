// clone-probe — a Go program for the sibling refusal (exec-routing.md §7.5
// gap (d)): what Go's runtime and standard library do to make threads and
// processes, run under the guard's seccomp filter. Built by
// clone_filter_integration.rs and the wrap-clone-filter sandbox test with
// `go build` (no module, no dependency), then run in the agent's tree.
//
// Go makes its threads with a raw clone(CLONE_VM|CLONE_THREAD|…) (the
// runtime's newosproc, no libc), its processes with a raw
// clone(CLONE_VFORK|CLONE_VM|CLONE_PIDFD) (syscall.forkAndExecInChild1, Go
// 1.23+ with a pidfd), and uses clone3 only for SysProcAttr.UseCgroupFD or
// CLONE_NEWTIME, with no fallback on ENOSYS.
//
// Usage: clone-probe open|refused. Each check prints `name=value`; any
// check that fails prints `FAIL <name>: <why>` and the exit is 1. `refused`
// also asserts the refusal: clone(CLONE_PARENT) EPERM, clone3 ENOSYS, Go's
// own Cloneflags=CLONE_PARENT spawn EPERM, and a UseCgroupFD spawn ENOSYS
// (Go's one clone3 path, the documented cost). The last line is `go-ok`.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var failed bool

func report(name string, value any) { fmt.Printf("%s=%v\n", name, value) }

func fail(name string, format string, a ...any) {
	failed = true
	fmt.Printf("FAIL %s: %s\n", name, fmt.Sprintf(format, a...))
}

// threads: goroutines, and OS threads the runtime must make (a goroutine
// locked to its thread and parked holds that thread).
func threads() {
	runtime.GOMAXPROCS(4)
	var wg sync.WaitGroup
	sums := make([]int, 1000)
	for i := range sums {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j <= i; j++ {
				sums[i] += j
			}
		}(i)
	}
	wg.Wait()
	if sums[999] != 999*1000/2 {
		fail("goroutines", "sum %d", sums[999])
	} else {
		report("goroutines", len(sums))
	}
	const locked = 16
	release := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	for i := 0; i < locked; i++ {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			ready.Done()
			<-release
		}()
	}
	ready.Wait()
	n := threadCount()
	close(release)
	done.Wait()
	if n < locked {
		fail("os_threads", "%d threads with %d goroutines locked to theirs", n, locked)
	} else {
		report("os_threads", "ok")
	}
}

func threadCount() int {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return -1
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		var n int
		if _, err := fmt.Sscanf(s.Text(), "Threads: %d", &n); err == nil {
			return n
		}
	}
	return -1
}

// pidfdHeld: does this process hold a pidfd (for a child it is waiting on)?
func pidfdHeld() bool {
	ents, _ := os.ReadDir("/proc/self/fd")
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.Contains(l, "pidfd") {
			return true
		}
	}
	return false
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

// spawns: os/exec in each shape, and os.StartProcess.
func spawns() {
	if c := exitCode(exec.Command("sh", "-c", "exit 3").Run()); c != 3 {
		fail("exec_run", "exit %d", c)
	} else {
		report("exec_run", 3)
	}
	if out, err := exec.Command("echo", "out").Output(); err != nil || strings.TrimSpace(string(out)) != "out" {
		fail("exec_output", "%q %v", out, err)
	} else {
		report("exec_output", "ok")
	}
	cat := exec.Command("cat")
	in, _ := cat.StdinPipe()
	outp, _ := cat.StdoutPipe()
	if err := cat.Start(); err != nil {
		fail("exec_pipes", "start: %v", err)
	} else {
		io.WriteString(in, "piped\n")
		in.Close()
		b, _ := io.ReadAll(outp)
		if err := cat.Wait(); err != nil || string(b) != "piped\n" {
			fail("exec_pipes", "%q %v", b, err)
		} else {
			report("exec_pipes", "ok")
		}
	}
	// A child killed through its handle (a pidfd where Go has one).
	sl := exec.Command("sleep", "30")
	if err := sl.Start(); err != nil {
		fail("exec_kill", "start: %v", err)
	} else {
		report("pidfd", pidfdHeld())
		sl.Process.Kill()
		err := sl.Wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			fail("exec_kill", "%v", err)
		} else {
			report("exec_kill", "ok")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	err := exec.CommandContext(ctx, "sleep", "30").Run()
	cancel()
	if err == nil || ctx.Err() == nil {
		fail("exec_context", "%v", err)
	} else {
		report("exec_context", "ok")
	}
	sh, _ := exec.LookPath("sh")
	p, err := os.StartProcess(sh, []string{"sh", "-c", "exit 4"}, &os.ProcAttr{Files: []*os.File{nil, os.Stdout, os.Stderr}})
	if err != nil {
		fail("start_process", "%v", err)
	} else if st, err := p.Wait(); err != nil || st.ExitCode() != 4 {
		fail("start_process", "%v %v", st, err)
	} else {
		report("start_process", 4)
	}
	// Concurrent spawns from many goroutines (syscall.ForkLock, the vfork path).
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := exec.Command("true").Run(); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err, ok := <-errs; ok {
		fail("exec_concurrent", "%v", err)
	} else {
		report("exec_concurrent", 40)
	}
}

// network: loopback TCP, an HTTP round trip, a unix socket, the resolver.
func network() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("tcp", "listen: %v", err)
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		fail("tcp", "dial: %v", err)
	} else {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		c.Write([]byte("echo\n"))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if line != "echo\n" {
			fail("tcp", "%q", line)
		} else {
			report("tcp", "ok")
		}
	}
	ln.Close()

	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("http", "listen: %v", err)
	} else {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") })}
		go srv.Serve(hl)
		cl := &http.Client{Timeout: 5 * time.Second}
		resp, err := cl.Get("http://" + hl.Addr().String() + "/")
		if err != nil {
			fail("http", "%v", err)
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "hello" {
				fail("http", "%q", b)
			} else {
				report("http", "ok")
			}
		}
		srv.Close()
	}

	dir, err := os.MkdirTemp("", "clone-probe-")
	if err == nil {
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "s")
		ul, err := net.Listen("unix", path)
		if err != nil {
			fail("unix", "listen: %v", err)
		} else {
			// A server that serves every connection: under a Unix allow-list
			// the guard's own probe of an unlisted listener (unix_owner.rs)
			// is the first one accepted, closed before a byte (exec-routing.md
			// §4.1); `unix_accepts` counts what the server took.
			var accepts int32
			go func() {
				for {
					c, err := ul.Accept()
					if err != nil {
						return
					}
					atomic.AddInt32(&accepts, 1)
					c.Write([]byte("u"))
					c.Close()
				}
			}()
			c, err := net.Dial("unix", path)
			if err != nil {
				fail("unix", "dial: %v", err)
			} else {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				b, rerr := io.ReadAll(c)
				c.Close()
				if string(b) != "u" {
					fail("unix", "read %q (%v) after %d accepts", b, rerr, atomic.LoadInt32(&accepts))
				} else {
					report("unix", "ok")
					report("unix_accepts", atomic.LoadInt32(&accepts))
				}
			}
			ul.Close()
		}
	}

	if addrs, err := net.LookupHost("localhost"); err != nil || len(addrs) == 0 {
		fail("resolve", "%v %v", addrs, err)
	} else {
		report("resolve", "ok")
	}
}

const (
	cloneParent     = 0x0000_8000
	cloneIntoCgroup = 0x2_0000_0000
	sysClone3       = 435
)

// cloneArgs is clone3's struct, CLONE_ARGS_SIZE_VER2 (88 bytes).
type cloneArgs struct {
	flags, pidfd, childTid, parentTid, exitSignal, stack, stackSize, tls, setTid, setTidSize, cgroup uint64
}

// refusals: only under the filter. A raw clone that succeeded here would
// fork a multi-threaded Go process; its child leaves at once.
func refusals() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, cloneParent|uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if r == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
	}
	if e != syscall.EPERM {
		fail("clone_parent", "clone(CLONE_PARENT) answered pid %d errno %d, not EPERM", r, e)
	} else {
		report("clone_parent", "EPERM")
	}
	args := cloneArgs{flags: cloneParent, exitSignal: uint64(syscall.SIGCHLD)}
	r, _, e = syscall.RawSyscall(sysClone3, uintptr(unsafe.Pointer(&args)), unsafe.Sizeof(args), 0)
	if r == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
	}
	if e != syscall.ENOSYS {
		fail("clone3_parent", "clone3(CLONE_PARENT) answered pid %d errno %d, not ENOSYS", r, e)
	} else {
		report("clone3_parent", "ENOSYS")
	}
	// Go's own API for the flag: SysProcAttr.Cloneflags goes into clone's
	// flags word (the vfork path), which the filter reads.
	c := exec.Command("true")
	c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneParent}
	if err := c.Run(); !errors.Is(err, syscall.EPERM) {
		fail("exec_clone_parent", "Cloneflags=CLONE_PARENT: %v, not EPERM", err)
	} else {
		report("exec_clone_parent", "EPERM")
	}
	// Go's one clone3 path (UseCgroupFD, CLONE_INTO_CGROUP) has no
	// fallback: under the refusal it fails with ENOSYS before the kernel
	// reads the cgroup (exec-routing.md §7.5 gap (d), the cost).
	cg, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		report("exec_cgroupfd", "no /sys/fs/cgroup")
		return
	}
	defer cg.Close()
	c = exec.Command("true")
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if err := c.Run(); !errors.Is(err, syscall.ENOSYS) {
		fail("exec_cgroupfd", "UseCgroupFD: %v, not ENOSYS", err)
	} else {
		report("exec_cgroupfd", "ENOSYS")
	}
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "open" && os.Args[1] != "refused") {
		fmt.Fprintln(os.Stderr, "usage: clone-probe open|refused")
		os.Exit(2)
	}
	report("go", runtime.Version())
	threads()
	spawns()
	network()
	if os.Args[1] == "refused" {
		refusals()
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("go-ok")
}
