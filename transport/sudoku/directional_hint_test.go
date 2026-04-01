package sudoku

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestDirectionalCustomTableRotationHintRoundTrip(t *testing.T) {
	key := "directional-rotate-key"
	target := "8.8.8.8:53"

	serverTables, err := NewServerTablesWithCustomPatterns(ClientAEADSeed(key), "up_ascii_down_entropy", "", []string{"xpxvvpvv", "vxpvxvvp"})
	if err != nil {
		t.Fatalf("server tables: %v", err)
	}
	if len(serverTables) != 2 {
		t.Fatalf("expected 2 server tables, got %d", len(serverTables))
	}

	clientTable, err := sudokuobfs.NewTableWithCustom(ClientAEADSeed(key), "up_ascii_down_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatalf("client table: %v", err)
	}

	serverCfg := DefaultConfig()
	serverCfg.Key = key
	serverCfg.AEADMethod = "chacha20-poly1305"
	serverCfg.Tables = serverTables
	serverCfg.PaddingMin = 0
	serverCfg.PaddingMax = 0
	serverCfg.EnablePureDownlink = true
	serverCfg.HandshakeTimeoutSeconds = 5
	serverCfg.DisableHTTPMask = true

	clientCfg := DefaultConfig()
	*clientCfg = *serverCfg
	clientCfg.ServerAddress = "example.com:443"

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer close(serverErr)
		defer serverConn.Close()

		c, meta, err := ServerHandshake(serverConn, serverCfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()

		session, err := ReadServerSession(c, meta)
		if err != nil {
			serverErr <- err
			return
		}
		if session.Type != SessionTypeTCP || session.Target != target {
			serverErr <- io.ErrUnexpectedEOF
			return
		}

		payload := make([]byte, len("client-payload"))
		if _, err := io.ReadFull(session.Conn, payload); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(payload, []byte("client-payload")) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}

		if _, err := session.Conn.Write([]byte("server-reply")); err != nil {
			serverErr <- err
		}
	}()

	seed := ClientAEADSeed(clientCfg.Key)
	obfsConn := buildClientObfsConn(clientConn, clientCfg, clientTable)
	pskC2S, pskS2C := derivePSKDirectionalBases(seed)
	cConn, err := crypto.NewRecordConn(obfsConn, clientCfg.AEADMethod, pskC2S, pskS2C)
	if err != nil {
		t.Fatalf("setup crypto: %v", err)
	}
	defer cConn.Close()

	if _, err := kipHandshakeClient(cConn, seed, kipUserHashFromKey(clientCfg.Key), KIPFeatAll, clientTable.Hint(), true); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	addrBuf, err := EncodeAddress(target)
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	if err := WriteKIPMessage(cConn, KIPTypeOpenTCP, addrBuf); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if _, err := cConn.Write([]byte("client-payload")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	reply := make([]byte, len("server-reply"))
	if _, err := io.ReadFull(cConn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !bytes.Equal(reply, []byte("server-reply")) {
		t.Fatalf("unexpected reply: %q", reply)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}
