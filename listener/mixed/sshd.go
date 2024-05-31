package mixed

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/gliderlabs/ssh"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"net"
	"time"
)

var sshServer ssh.Server

type sshConn struct {
	net.Conn
	closeCallback func()
	ctx           ssh.Context
}

var (
	DeadlineTimeout = 30 * time.Second
	IdleTimeout     = 10 * time.Second
	tunnel          C.Tunnel
)

func InitSShServer(tunnel_ C.Tunnel) {
	tunnel = tunnel_
	sshServer = ssh.Server{
		PasswordHandler: passwordHandler,

		ConnectionFailedCallback: sshConnectionFailed,
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			//log.Println("Accepted forward", dhost, dport)
			return true
		}),

		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": DirectTCPIPHandler,
			"session":      SessionHandler,
		},
		PtyCallback: func(ctx ssh.Context, pty ssh.Pty) bool {
			return false
		},
		//MaxTimeout:  DeadlineTimeout,
		//IdleTimeout: IdleTimeout,
	}

	//if len(sshServer.HostSigners) == 0 {
	//	signer, err := generateSigner()
	//	if err != nil {
	//
	//		log.Panicf("%v", err)
	//	}
	//	sshServer.HostSigners = append(sshServer.HostSigners, signer)
	//}
	sshServer.SetOption(HostKeyFile())

}

func passwordHandler(ctx ssh.Context, password string) bool {
	author := authStore.Authenticator()
	if inbound.SkipAuthRemoteAddr(ctx.RemoteAddr()) {
		author = nil
	}
	if author == nil {
		return true
	}
	if author.Verify(ctx.User(), password) {
		return true
	}
	return false
}

func sshConnectionFailed(conn net.Conn, err error) {
	// Log the underlying error with a specific message
	log.Warnf("ssh: Failed connection from %s with error: %v", conn.RemoteAddr(), err)

}

func DirectTCPIPHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	d := inbound.LocalForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	//dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	//var dialer net.Dialer
	//dconn, err := dialer.DialContext(ctx, "tcp", dest)
	//if err != nil {
	//	newChan.Reject(gossh.ConnectionFailed, err.Error())
	//	return
	//}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		//dconn.Close()
		return
	}
	//go gossh.DiscardRequests(reqs)
	breakout := make(chan struct{})
	go func() {
		for {
			select {
			case req := <-reqs:
				if req != nil && req.WantReply {
					req.Reply(false, nil)
				}
			case <-breakout:
				return

			}
		}
	}()

	//go func() {
	//	defer ch.Close()
	//	defer dconn.Close()
	//	io.Copy(ch, dconn)
	//}()
	//go func() {
	//	defer ch.Close()
	//	defer dconn.Close()
	//	io.Copy(dconn, ch)
	//}()

	sshConn := inbound.MySSHConn{
		Channel:     ch,
		LocalAddr_:  conn.LocalAddr(),
		RemoteAddr_: conn.RemoteAddr(),
	}
	metadata := inbound.NewSSH(&d, &sshConn, C.SSH)
	if !metadata.Valid() {
		log.Warnln("ssh not valid: %#v", newChan.ExtraData())
	}
	go func(breakout chan<- struct{}) {
		defer sshConn.Close()
		defer func() {
			breakout <- struct{}{}
		}()
		tunnel.HandleTCPConn(&sshConn, metadata)
	}(breakout)
}

func SessionHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	defer func() {
		conn.Close()
	}()
	ch, _, err := newChan.Accept()
	if err != nil {

		return
	}
	defer func() {
		ch.Close()
	}()
	var chars [1]byte
	for {
		_, err := ch.Read(chars[:])
		if err != nil {
			break
		}
		_, err = ch.Write(chars[:])
		if err != nil {
			break
		}
		//log.Infof("%d", chars[0])
		if chars[0] == 3 || chars[0] == 26 { //ctr-c == 3  ctr-z == 26
			break
		}
	}
}

var ed25519_key = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCBH8jSvR0eyMdieVjyup2TKrtaCbB2WZzzYGKxdGLISQAAAKAVISnTFSEp
0wAAAAtzc2gtZWQyNTUxOQAAACCBH8jSvR0eyMdieVjyup2TKrtaCbB2WZzzYGKxdGLISQ
AAAEDl+FO3qPfVkYDbrC94EapwmxOYOzAHpRSz0bueb7dWI4EfyNK9HR7Ix2J5WPK6nZMq
u1oJsHZZnPNgYrF0YshJAAAAHHJvb3RAaVpicDE4dDI5bTNvNjE4OTg4b3RibloB
-----END OPENSSH PRIVATE KEY-----
`

func HostKeyFile() ssh.Option {
	return func(srv *ssh.Server) error {

		signer, err := gossh.ParsePrivateKey([]byte(ed25519_key))
		if err != nil {
			return err
		}
		srv.AddHostKey(signer)
		return nil
	}
}

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(key)
}
