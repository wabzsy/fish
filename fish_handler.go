//go:build !windows
// +build !windows

package fish

import (
	"fish/utils"
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

func DefaultCommand(sess ssh.Session) string {
	zsh := "/bin/zsh"
	bash := "/bin/bash"
	sh := "/bin/sh"

	shell, ok := sess.Context().Value("SHELL").(string)
	if ok && shell != "" {
		return shell
	} else if utils.FileExists(zsh) {
		return zsh
	} else if utils.FileExists(bash) {
		return bash
	} else {
		return sh
	}
}

func sshHandler(sess ssh.Session) {
	defer func() {
		_ = sess.Exit(0)
	}()

	userHomeDir := sess.Context().Value("HOME")
	userShell := sess.Context().Value("SHELL")
	userUid, ok := sess.Context().Value("UID").(uint32)
	if !ok {
		log.Printf("[ERROR] bad UID for user: %s", sess.User())
		return
	}

	userGid, ok := sess.Context().Value("GID").(uint32)
	if !ok {
		log.Printf("[ERROR] bad GID for user: %s", sess.User())
		return
	}

	cmd := GetCommand(sess)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: userUid,
			Gid: userGid,
			//NoSetGroups: true,
		},
		//Setpgid: true,
	}

	// export HISTFILE=/dev/null
	cmd.Env = sess.Environ()
	cmd.Dir = fmt.Sprintf("%s", userHomeDir)
	cmd.Env = append(cmd.Env, []string{
		//"HISTFILE=/dev/null",
		//"HISTSIZE=0",
		//"HISTFILESIZE=0",
		//"LC_ALL=en_US.UTF-8",
		//"LC_CTYPE=en_US.UTF-8",
		//"LANG=en_US.UTF-8",
		"PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
		fmt.Sprintf("HOME=%s", userHomeDir),
		fmt.Sprintf("PWD=%s", userHomeDir),
		fmt.Sprintf("USER=%s", sess.User()),
		fmt.Sprintf("LOGNAME=%s", sess.User()),
		fmt.Sprintf("SHELL=%s", userShell),
	}...)

	ptyReq, winCh, isPty := sess.Pty()

	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			writeError(sess, fmt.Errorf("PTY start failed.\n"))
			return
		}

		go func() {
			for win := range winCh {
				setWinSize(f, win.Width, win.Height)
			}
		}()

		doneCh := make(chan bool, 1)
		var once sync.Once

		done := func() {
			_ = cmd.Wait()
			_ = f.Close()
			doneCh <- true
		}

		go func() {
			_, _ = io.Copy(f, sess) // stdin
			once.Do(done)
		}()
		go func() {
			_, _ = io.Copy(sess, f) // stdout
			once.Do(done)
		}()

		<-doneCh
	} else {
		var once sync.Once

		stdin, err := cmd.StdinPipe()
		if err != nil {
			writeError(sess, err)
			return
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			writeError(sess, err)
			return
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			writeError(sess, err)
			return
		}

		done := func() {
			_ = stdin.Close()
			_ = stdout.Close()
			_ = stderr.Close()
		}

		go func() {
			_, _ = io.Copy(stdin, sess) // stdin
			once.Do(done)
		}()

		go func() {
			_, _ = io.Copy(sess, stdout) // stdout
			once.Do(done)
		}()

		go func() {
			_, _ = io.Copy(sess, stderr) // stderr
			once.Do(done)
		}()

		if err := cmd.Run(); err != nil {
			//fmt.Println(err)
			writeError(sess, err)
		}
	}
}

func setWinSize(f *os.File, w, h int) {
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCSWINSZ),
		uintptr(
			unsafe.Pointer(
				&struct {
					h, w, x, y uint16
				}{
					uint16(h),
					uint16(w),
					uint16(0),
					uint16(0),
				},
			),
		),
	)
}
