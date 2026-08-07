package openvpn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func TestClientCompletesSequentialSoftResetEpochs(t *testing.T) {
	testClientCompletesSequentialSoftResetEpochs(t, false, false)
}

func TestClientUsesFixedAuthTokenAcrossSoftResetEpochs(t *testing.T) {
	testClientCompletesSequentialSoftResetEpochs(t, true, false)
}

func TestClientUsesRefreshedAuthTokenAcrossSoftResetEpochs(t *testing.T) {
	testClientCompletesSequentialSoftResetEpochs(t, true, true)
}

func testClientCompletesSequentialSoftResetEpochs(t *testing.T, useAuthToken, refreshAuthToken bool) {
	serverCert, caPEM := testRekeyServerCertificate(t)
	config := &ClientConfig{
		RemoteHost: "127.0.0.1",
		RemotePort: 1194,
		Proto:      ProtoUDP,
		Dev:        "tun",
		Cipher:     CipherAES128CBC,
		Auth:       AuthSHA1,
		CA:         caPEM,
		Username:   "testuser",
		Password:   "testpass",
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}

	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverMux := NewPacketMux(serverIO)
	go serverMux.Run(ctx)
	defer serverMux.Close()

	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	serverControl := NewControlChannel(serverMux, nil, serverID)
	serverControl.SetRemoteSessionID(client.control.LocalSessionID())
	client.control.SetRemoteSessionID(serverID)

	initialResult := make(chan initialServerResult, 1)
	go func() {
		clientRecord, err := serveOpenVPNInitialEpoch(ctx, serverControl, serverCert, useAuthToken)
		initialResult <- initialServerResult{clientRecord: clientRecord, err: err}
	}()

	tlsConfig, err := client.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	initialTLS := tls.Client(NewControlConn(client.control), tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = initialTLS.SetDeadline(deadline)
	}
	if err := initialTLS.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	push, err := client.doKeyExchange(ctx, initialTLS, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = initialTLS.SetDeadline(time.Time{})
	if !client.setTLSConn(initialTLS) {
		t.Fatal("failed to publish initial TLS connection")
	}
	result := <-initialResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.clientRecord.Username != config.Username || result.clientRecord.Password != config.Password {
		t.Fatalf(
			"initial credentials = (%q, %q); want (%q, %q)",
			result.clientRecord.Username,
			result.clientRecord.Password,
			config.Username,
			config.Password,
		)
	}
	if useAuthToken {
		if push.AuthToken != "token-0" || push.AuthTokenUser != "token-user" {
			t.Fatalf("initial push token = (%q, %q); want token-0 and token-user", push.AuthToken, push.AuthTokenUser)
		}
	}
	go client.watchControl()

	previousTLS := initialTLS
	serverDataByKey := make(map[uint8]*DataChannel, 2)
	for epochIndex, expectedKeyID := range []uint8{1, 2} {
		if err := serverControl.SendSoftReset(ctx); err != nil {
			t.Fatal(err)
		}

		serverResult := make(chan rekeyServerResult, 1)
		refreshedAuthToken := ""
		var refreshGate chan struct{}
		var refreshDone chan error
		if useAuthToken && refreshAuthToken {
			refreshedAuthToken = fmt.Sprintf("token-%d", epochIndex+1)
			refreshGate = make(chan struct{})
			refreshDone = make(chan error, 1)
		}
		go func() {
			data, clientRecord, err := serveOpenVPNRekeyEpoch(
				ctx,
				serverControl,
				serverCert,
				refreshedAuthToken,
				refreshGate,
				refreshDone,
			)
			serverResult <- rekeyServerResult{data: data, clientRecord: clientRecord, err: err}
		}()
		result := <-serverResult
		if result.err != nil {
			t.Fatalf("server rekey failed: %v (client error: %v)", result.err, client.Err())
		}
		expectedUsername := config.Username
		expectedPassword := config.Password
		if useAuthToken {
			expectedUsername = "token-user"
			expectedPassword = "token-0"
			if refreshAuthToken {
				expectedPassword = fmt.Sprintf("token-%d", epochIndex)
			}
		}
		if result.clientRecord.Username != expectedUsername || result.clientRecord.Password != expectedPassword {
			t.Fatalf(
				"key epoch %d credentials = (%q, %q); want (%q, %q)",
				expectedKeyID,
				result.clientRecord.Username,
				result.clientRecord.Password,
				expectedUsername,
				expectedPassword,
			)
		}
		serverDataByKey[expectedKeyID] = result.data

		currentTLS, err := waitForClientEpoch(ctx, client, expectedKeyID, previousTLS)
		if err != nil {
			t.Fatal(err)
		}
		previousTLS = currentTLS

		client.dataLock.RLock()
		activeData := client.data
		_, hasActive := client.dataByKey[expectedKeyID]
		_, hasPrevious := client.dataByKey[nextPreviousKeyID(expectedKeyID)]
		dataChannelCount := len(client.dataByKey)
		client.dataLock.RUnlock()
		if activeData == nil || activeData.keyID != expectedKeyID || !hasActive || !hasPrevious {
			t.Fatalf("unexpected data epochs after rekey: active=%v keys=%v", activeData, clientDataKeyIDs(client))
		}
		if dataChannelCount != 2 {
			t.Fatalf("data channel count = %d; want 2", dataChannelCount)
		}

		if refreshGate != nil {
			select {
			case err := <-refreshDone:
				t.Fatalf("auth token refresh completed before the new data epoch was active: %v", err)
			default:
			}
			close(refreshGate)
			select {
			case err := <-refreshDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := waitForClientPassword(ctx, client, refreshedAuthToken); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, keyID := range []uint8{1, 2} {
		want := []byte(fmt.Sprintf("packet from key epoch %d", keyID))
		packet, err := serverDataByKey[keyID].Encrypt(want)
		if err != nil {
			t.Fatal(err)
		}
		if err := serverIO.WritePacket(ctx, packet); err != nil {
			t.Fatal(err)
		}
		got, err := client.ReadIPPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("key epoch %d packet = %q; want %q", keyID, got, want)
		}
	}
}

type rekeyServerResult struct {
	data         *DataChannel
	clientRecord *KeyMethod2Record
	err          error
}

type initialServerResult struct {
	clientRecord *KeyMethod2Record
	err          error
}

func serveOpenVPNInitialEpoch(
	ctx context.Context,
	control *ControlChannel,
	serverCert tls.Certificate,
	pushAuthToken bool,
) (*KeyMethod2Record, error) {
	tlsConn := tls.Server(NewControlConn(control), &tls.Config{Certificates: []tls.Certificate{serverCert}})
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("initial server TLS handshake: %w", err)
	}

	clientRecord, err := readClientKeyMethod2Record(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("read initial client key method record: %w", err)
	}
	_, serverBytes, err := testServerKeyMethodRecord()
	if err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write(serverBytes); err != nil {
		return nil, fmt.Errorf("write initial server key method record: %w", err)
	}
	message, _, err := readTLSControlMessage(ctx, tlsConn, nil)
	if err != nil {
		return nil, fmt.Errorf("read initial push request: %w", err)
	}
	if message != PushRequest {
		return nil, fmt.Errorf("initial control message = %q; want %q", message, PushRequest)
	}
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 7,cipher AES-128-CBC"
	if pushAuthToken {
		pushReply += ",auth-token token-0,auth-token-user dG9rZW4tdXNlcg=="
	}
	if _, err := tlsConn.Write([]byte(pushReply + "\x00")); err != nil {
		return nil, fmt.Errorf("write initial push reply: %w", err)
	}
	return clientRecord, nil
}

func serveOpenVPNRekeyEpoch(
	ctx context.Context,
	control *ControlChannel,
	serverCert tls.Certificate,
	refreshedAuthToken string,
	refreshGate <-chan struct{},
	refreshDone chan<- error,
) (*DataChannel, *KeyMethod2Record, error) {
	reset, err := control.Read(ctx)
	if err != nil {
		return nil, nil, err
	}
	if reset.Opcode != PControlSoftResetV1 {
		return nil, nil, fmt.Errorf("unexpected client rekey opcode %s", reset.Opcode)
	}
	if err := control.SendAck(ctx); err != nil {
		return nil, nil, err
	}

	tlsConn := tls.Server(NewControlConn(control), &tls.Config{Certificates: []tls.Certificate{serverCert}})
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("server TLS handshake: %w", err)
	}

	clientRecord, err := readClientKeyMethod2Record(tlsConn)
	if err != nil {
		return nil, nil, fmt.Errorf("read client key method record: %w", err)
	}

	serverRecord, serverBytes, err := testServerKeyMethodRecord()
	if err != nil {
		return nil, nil, err
	}
	if _, err := tlsConn.Write(serverBytes); err != nil {
		return nil, nil, fmt.Errorf("write server key method record: %w", err)
	}
	if refreshedAuthToken != "" {
		go func() {
			select {
			case <-refreshGate:
				_, err := tlsConn.Write([]byte(fmt.Sprintf(
					"PUSH_REPLY,auth-token %s\x00",
					refreshedAuthToken,
				)))
				if err != nil {
					err = fmt.Errorf("write refreshed auth token: %w", err)
				}
				refreshDone <- err
			case <-ctx.Done():
				refreshDone <- ctx.Err()
			}
		}()
	}

	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	clientKeys, err := DeriveClientKeyMaterial(sources, control.RemoteSessionID(), control.LocalSessionID(), 16)
	if err != nil {
		return nil, nil, err
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	data, err := newDataChannel(serverKeys, CipherAES128CBC, AuthSHA1, 7, reset.KeyID)
	return data, clientRecord, err
}

func waitForClientPassword(ctx context.Context, client *Client, password string) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		_, currentPassword := client.keyMethodCredentials()
		if currentPassword == password {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitForClientEpoch(ctx context.Context, client *Client, keyID uint8, previousTLS *tls.Conn) (*tls.Conn, error) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := client.Err(); err != nil {
			return nil, err
		}
		client.dataLock.RLock()
		active := client.data
		client.dataLock.RUnlock()
		client.tlsLock.Lock()
		currentTLS := client.tlsConn
		client.tlsLock.Unlock()
		if active != nil && active.keyID == keyID && currentTLS != nil && currentTLS != previousTLS {
			return currentTLS, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func readClientKeyMethod2Record(tlsConn *tls.Conn) (*KeyMethod2Record, error) {
	var packet []byte
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if err != nil {
			return nil, err
		}
		packet = append(packet, tmp[:n]...)
		recordLength, complete, err := clientKeyMethod2RecordLength(packet)
		if err != nil {
			return nil, err
		}
		if !complete {
			continue
		}
		const fixedLength = 4 + 1 + keySourcePreMasterSize + 2*keySourceRandomSize
		record := &KeyMethod2Record{}
		offset := 5
		copy(record.Sources.Client.PreMaster[:], packet[offset:offset+keySourcePreMasterSize])
		offset += keySourcePreMasterSize
		copy(record.Sources.Client.Random1[:], packet[offset:offset+keySourceRandomSize])
		offset += keySourceRandomSize
		copy(record.Sources.Client.Random2[:], packet[offset:fixedLength])
		offset = fixedLength
		record.Options, offset, err = readOpenVPNString(packet[:recordLength], offset)
		if err != nil {
			return nil, err
		}
		record.Username, offset, err = readOpenVPNString(packet[:recordLength], offset)
		if err != nil {
			return nil, err
		}
		record.Password, offset, err = readOpenVPNString(packet[:recordLength], offset)
		if err != nil {
			return nil, err
		}
		record.PeerInfo, _, err = readOpenVPNString(packet[:recordLength], offset)
		if err != nil {
			return nil, err
		}
		return record, nil
	}
}

func clientKeyMethod2RecordLength(packet []byte) (int, bool, error) {
	const fixedLength = 4 + 1 + keySourcePreMasterSize + 2*keySourceRandomSize
	if len(packet) < fixedLength {
		return 0, false, nil
	}
	if binary.BigEndian.Uint32(packet[:4]) != 0 || packet[4]&0x0f != KeyMethod2 {
		return 0, false, fmt.Errorf("unexpected client key method record prefix %x", packet[:5])
	}
	offset := fixedLength
	for i := 0; i < 4; i++ {
		if len(packet) < offset+2 {
			return 0, false, nil
		}
		length := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
		offset += 2
		if len(packet) < offset+length {
			return 0, false, nil
		}
		offset += length
	}
	return offset, true, nil
}

func testRekeyServerCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mihomo-openvpn-test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return serverCert, certPEM
}

func testServerKeyMethodRecord() (*KeyMethod2Record, []byte, error) {
	serverRecord := &KeyMethod2Record{}
	record := binary.BigEndian.AppendUint32(nil, 0)
	record = append(record, KeyMethod2)
	randomBytes := make([]byte, 2*keySourceRandomSize)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, nil, err
	}
	copy(serverRecord.Sources.Server.Random1[:], randomBytes[:keySourceRandomSize])
	copy(serverRecord.Sources.Server.Random2[:], randomBytes[keySourceRandomSize:])
	record = append(record, randomBytes...)
	record = appendOpenVPNString(record, "V4,dev-type tun,cipher AES-128-CBC,auth SHA1,key-method 2,tls-server")
	record = appendOpenVPNString(record, "")
	record = appendOpenVPNString(record, "")
	record = appendOpenVPNString(record, "")
	return serverRecord, record, nil
}

func testEpochKeys(seed byte) *KeyMaterial {
	key := func(offset byte, size int) []byte {
		out := make([]byte, size)
		for i := range out {
			out[i] = seed + offset
		}
		return out
	}
	return &KeyMaterial{
		SendCipherKey: key(1, 16),
		SendHMACKey:   key(2, maxHMACKeyLength),
		RecvCipherKey: key(3, 16),
		RecvHMACKey:   key(4, maxHMACKeyLength),
	}
}

func nextPreviousKeyID(keyID uint8) uint8 {
	if keyID == 1 {
		return 0
	}
	return keyID - 1
}

func clientDataKeyIDs(client *Client) []uint8 {
	client.dataLock.RLock()
	defer client.dataLock.RUnlock()
	keyIDs := make([]uint8, 0, len(client.dataByKey))
	for keyID := range client.dataByKey {
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}
