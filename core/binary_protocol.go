package core

import (
	"encoding/binary"
	"io"
)

type BinaryPacketHeader struct {
	PacketLength  uint32
	PaddingLength byte
}

type BinaryPacketBody struct {
	Payload       []byte
	RandomPadding []byte
}

type BinaryPacketMacHeader struct {
	MacLength byte
}

type BinaryPacketMacBody struct {
	Mac []byte
}

type BinaryPacket struct {
	Header    *BinaryPacketHeader
	Body      *BinaryPacketBody
	MacHeader *BinaryPacketMacHeader
	MacBody   *BinaryPacketMacBody
}

func NewBinaryPacket() *BinaryPacket {
	return &BinaryPacket{
		Header: &BinaryPacketHeader{
			PacketLength:  0,
			PaddingLength: 0,
		},
		Body: &BinaryPacketBody{
			Payload:       []byte{},
			RandomPadding: []byte{},
		},
		MacHeader: &BinaryPacketMacHeader{
			MacLength: 0,
		},
		MacBody: &BinaryPacketMacBody{
			Mac: []byte{},
		},
	}
}

func (header *BinaryPacketHeader) Parse(r io.Reader) error {
	err := binary.Read(r, binary.BigEndian, header)
	return err
}

func (packet *BinaryPacket) ParseBody(r io.Reader) error {
	n0 := int(packet.Header.PacketLength)
	n2 := int(packet.Header.PaddingLength)
	n1 := n0 - n2 - 1

	packet.Body.Payload = make([]byte, n1)
	packet.Body.RandomPadding = make([]byte, n2)

	err := binary.Read(r, binary.BigEndian, packet.Body.Payload)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.BigEndian, packet.Body.RandomPadding)
	if err != nil {
		return err
	}

	return err
}

func (macHeader *BinaryPacketMacHeader) Parse(r io.Reader) error {
	return binary.Read(r, binary.BigEndian, macHeader)
}

func (packet *BinaryPacket) ParseMacBody(r io.Reader) error {
	m := int(packet.MacHeader.MacLength)

	packet.MacBody.Mac = make([]byte, m)

	err := binary.Read(r, binary.BigEndian, packet.MacBody.Mac)
	if err != nil {
		return err
	}

	return nil
}

func (packet *BinaryPacket) Parse(r io.Reader, skipMac bool) error {
	err := packet.Header.Parse(r)
	if err != nil {
		return err
	}

	err = packet.ParseBody(r)
	if err != nil {
		return err
	}

	if !skipMac {
		err := packet.MacHeader.Parse(r)
		if err != nil {
			return err
		}

		err = packet.ParseMacBody(r)
		if err != nil {
			return err
		}
	}

	return nil
}
