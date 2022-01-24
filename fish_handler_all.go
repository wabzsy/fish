package fish

import (
	"github.com/gliderlabs/ssh"
	"os/exec"
)

func GetCommand(session ssh.Session) *exec.Cmd {
	remoteCommand := session.Command()
	if len(remoteCommand) == 0 {
		remoteCommand = []string{DefaultCommand(session)}
	}
	return exec.Command(remoteCommand[0], remoteCommand[1:]...)
}

func writeError(session ssh.Session, err error) {
	_, _ = session.Write([]byte(err.Error() + "\n"))
	_ = session.Exit(2)
}
