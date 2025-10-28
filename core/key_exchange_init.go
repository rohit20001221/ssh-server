package core

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"strings"
)

type KeyExchangeHeader struct {
	Message []byte
	Cookie  []byte
}

func NewKeyExchangeHeader() *KeyExchangeHeader {
	return &KeyExchangeHeader{
		Message: make([]byte, 1),
		Cookie:  make([]byte, 16),
	}
}

func (kh *KeyExchangeHeader) Parse(r io.Reader) error {
	err := binary.Read(r, binary.BigEndian, kh.Message)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, kh.Cookie)
	if err != nil {
		return err
	}

	return nil
}

type NameList struct {
	Len  uint32
	Data []byte
}

func NewNameList() *NameList {
	return &NameList{
		Len:  0,
		Data: []byte{},
	}
}

func (nl *NameList) Parse(r io.Reader) error {
	err := binary.Read(r, binary.BigEndian, &nl.Len)
	if err != nil {
		return err
	}

	nl.Data = make([]byte, nl.Len)
	err = binary.Read(r, binary.BigEndian, nl.Data)
	if err != nil {
		return err
	}

	return nil
}

func ProcessNameListItem(r io.Reader) ([]string, error) {
	nl := NewNameList()
	err := nl.Parse(r)
	if err != nil {
		return []string{}, err
	}

	log.Println(string(nl.Data))
	return strings.Split(string(nl.Data), ","), nil
}

type KeyExchangeBody struct {
	KexAlgorithms                     []string
	ServerHostKeyAlgorithms           []string
	EncryptionAlgorithmsClientServer  []string
	EncryptionAlgorithmsServerClient  []string
	MacAlgorithmsClientServer         []string
	MacAlgorithmsServerClient         []string
	CompressionAlgorithmsClientServer []string
	CompressionAlgorithmsServerClient []string
	LanguagesClientServer             []string
	LanguagesServerClient             []string
	IsFirstKexPacketFollows           bool
	ReservedByte                      uint32
}

func NewKeyExchangeBody() *KeyExchangeBody {
	return &KeyExchangeBody{
		KexAlgorithms:                     []string{},
		ServerHostKeyAlgorithms:           []string{},
		EncryptionAlgorithmsClientServer:  []string{},
		EncryptionAlgorithmsServerClient:  []string{},
		MacAlgorithmsClientServer:         []string{},
		MacAlgorithmsServerClient:         []string{},
		CompressionAlgorithmsClientServer: []string{},
		CompressionAlgorithmsServerClient: []string{},
		LanguagesClientServer:             []string{},
		LanguagesServerClient:             []string{},
		IsFirstKexPacketFollows:           false,
		ReservedByte:                      0,
	}
}

func (kb *KeyExchangeBody) Parse(r io.Reader) error {
	var err error

	if kb.KexAlgorithms, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.ServerHostKeyAlgorithms, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.EncryptionAlgorithmsClientServer, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.EncryptionAlgorithmsServerClient, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.MacAlgorithmsClientServer, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.MacAlgorithmsServerClient, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.CompressionAlgorithmsClientServer, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.CompressionAlgorithmsServerClient, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.LanguagesClientServer, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if kb.LanguagesServerClient, err = ProcessNameListItem(r); err != nil {
		return err
	}

	if err = binary.Read(r, binary.BigEndian, &kb.IsFirstKexPacketFollows); err != nil {
		return err
	}

	if err = binary.Read(r, binary.BigEndian, &kb.ReservedByte); err != nil {
		return err
	}

	return nil
}

func GenerateKexPacket() ([]byte, error) {
	packet := make([]byte, 0)

	/* Header Generation */
	kexHeader := NewKeyExchangeHeader()

	kexHeader.Message = []byte{SSH_MSG_KEXINIT}
	kexHeader.Cookie = make([]byte, 16)

	_, err := rand.Read(kexHeader.Cookie)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, kexHeader.Message)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, kexHeader.Cookie)
	if err != nil {
		return packet, err
	}

	/* Body Generation */

	KexAlgorithmsList := []string{
		"diffie-hellman-group-exchange-sha256",
		"sntrup761x25519-sha512",
		"sntrup761x25519-sha512@openssh.com",
		"mlkem768x25519-sha256",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512",
		"diffie-hellman-group14-sha256",
		"ext-info-c",
		"kex-strict-c-v00@openssh.com",
	}

	KexAlgorithms := []byte(strings.Join(KexAlgorithmsList, ","))
	KexAlgorithmsLength := uint32(len(KexAlgorithms))

	packet, err = binary.Append(packet, binary.BigEndian, KexAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, KexAlgorithms)
	if err != nil {
		return packet, err
	}

	ServerHostKeyAlgorithmsList := []string{
		"rsa-sha2-256",
		"ssh-ed25519-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"sk-ssh-ed25519-cert-v01@openssh.com",
		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"rsa-sha2-512-cert-v01@openssh.com",
		"rsa-sha2-256-cert-v01@openssh.com",
		"ssh-ed25519",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com",
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"rsa-sha2-512",
	}

	ServerHostKeyAlgorithms := []byte(strings.Join(ServerHostKeyAlgorithmsList, ","))
	ServerHostKeyAlgorithmsLength := uint32(len(ServerHostKeyAlgorithms))

	packet, err = binary.Append(packet, binary.BigEndian, ServerHostKeyAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, ServerHostKeyAlgorithms)
	if err != nil {
		return packet, err
	}

	EncryptionAlgorithmsList := []string{
		"aes256-ctr",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
	}

	EncryptionAlgorithms := []byte(strings.Join(EncryptionAlgorithmsList, ","))
	EncryptionAlgorithmsLength := uint32(len(EncryptionAlgorithms))

	// Client to Server
	packet, err = binary.Append(packet, binary.BigEndian, EncryptionAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, EncryptionAlgorithms)
	if err != nil {
		return packet, err
	}

	// Server to Client
	packet, err = binary.Append(packet, binary.BigEndian, EncryptionAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, EncryptionAlgorithms)
	if err != nil {
		return packet, err
	}

	MacAlgorithmsList := []string{
		"hmac-sha2-256",
		"umac-64-etm@openssh.com",
		"umac-128-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com",
		"umac-64@openssh.com",
		"umac-128@openssh.com",
		"hmac-sha2-512",
		"hmac-sha1",
	}

	MacAlgorithms := []byte(strings.Join(MacAlgorithmsList, ","))
	MacAlgorithmsLength := uint32(len(MacAlgorithms))

	// client to server
	packet, err = binary.Append(packet, binary.BigEndian, MacAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, MacAlgorithms)
	if err != nil {
		return packet, err
	}

	// server to client
	packet, err = binary.Append(packet, binary.BigEndian, MacAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, MacAlgorithms)
	if err != nil {
		return packet, err
	}

	CompressionAlgorithmsList := []string{
		"none",
		"zlib@openssh.com",
	}

	CompressionAlgorithms := []byte(strings.Join(CompressionAlgorithmsList, ","))
	CompressionAlgorithmsLength := uint32(len(CompressionAlgorithms))

	// client to server
	packet, err = binary.Append(packet, binary.BigEndian, CompressionAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, CompressionAlgorithms)
	if err != nil {
		return packet, err
	}

	// server to client
	packet, err = binary.Append(packet, binary.BigEndian, CompressionAlgorithmsLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, CompressionAlgorithms)
	if err != nil {
		return packet, err
	}

	LanguagesList := []string{""}
	Languages := []byte(strings.Join(LanguagesList, ","))
	LanguagesLength := uint32(len(Languages))

	// client to server
	packet, err = binary.Append(packet, binary.BigEndian, LanguagesLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, Languages)
	if err != nil {
		return packet, err
	}

	// server to client
	packet, err = binary.Append(packet, binary.BigEndian, LanguagesLength)
	if err != nil {
		return packet, err
	}

	packet, err = binary.Append(packet, binary.BigEndian, Languages)
	if err != nil {
		return packet, err
	}

	// packet follow
	packet, err = binary.Append(packet, binary.BigEndian, false)
	if err != nil {
		return packet, err
	}

	// reserved bit
	packet, err = binary.Append(packet, binary.BigEndian, uint32(0))
	if err != nil {
		return packet, err
	}

	/* Add Padding if nessary */
	BLOCK_SIZE := 16
	PaddingRequired := uint32(len(packet) % BLOCK_SIZE)

	if PaddingRequired > 0 {
		for range PaddingRequired {
			packet = append(packet, byte(0))
		}
	}

	packet = append([]byte{byte(PaddingRequired)}, packet...)
	PacketLength := len(packet)
	packet = append([]byte{byte(PacketLength)}, packet...)

	log.Println("[x] length of kex packet from server:", len(packet), len(packet)%BLOCK_SIZE)

	return packet, err
}

func InitKeyExchange(r io.Reader, w io.Writer) error {
	packet := NewBinaryPacket()

	err := packet.Parse(r, true) // skip the mac in initial request
	if err != nil {
		return err
	}

	log.Println(packet.Header)
	log.Println(string(packet.Body.Payload))
	log.Println(string(packet.Body.RandomPadding))

	payloadReader := bytes.NewReader(packet.Body.Payload)

	keyExchangeHeader := NewKeyExchangeHeader()
	err = keyExchangeHeader.Parse(payloadReader)
	if err != nil {
		return err
	}

	log.Println(keyExchangeHeader.Message, string(keyExchangeHeader.Cookie))

	kexBody := NewKeyExchangeBody()
	err = kexBody.Parse(payloadReader)
	if err != nil {
		return err
	}

	log.Println(kexBody)

	kexPacket, err := GenerateKexPacket()
	if err != nil {
		return err
	}

	_, err = w.Write(kexPacket)

	return err
}
