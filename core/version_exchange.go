package core

import "io"

func ExchangeProtocolVersion(writer io.Writer) (int, error) {
	return writer.Write([]byte("SSH-2.0-GOSSH\r\n"))
}
