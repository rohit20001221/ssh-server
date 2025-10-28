package core

import (
	"io"
)

func InitKeyExchange(r io.Reader, w io.Writer) error {
	packet := NewBinaryPacket()

	err := packet.Decode(r, nil)
	if err != nil {
		return err
	}

	return err
}
