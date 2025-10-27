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

	return packet, err
}

func InitKeyExchange(r io.Reader) error {
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

	log.Println(string(kexPacket))

	return err
}
