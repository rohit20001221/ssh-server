package core

import (
	"bytes"
	"io"
)

type SSH struct {
	Reader       io.Reader
	Writer       io.Writer
	MacAlgorithm string
	MacLength    uint32
}

func NewSSH(r io.Reader, w io.Writer) *SSH {
	return &SSH{
		Reader:       r,
		Writer:       w,
		MacAlgorithm: "",
		MacLength:    0,
	}
}

func (s *SSH) Read() (*BinaryPacket, error) {
	packet := NewBinaryPacket()
	if err := packet.Decode(s.Reader); err != nil {
		return nil, err
	}

	return packet, nil
}

func (s *SSH) Write(packet *BinaryPacket) error {
	buf := new(bytes.Buffer)
	if err := packet.Encode(buf); err != nil {
		return err
	}

	s.Writer.Write(buf.Bytes())
	return nil
}
