package core

func (s *SSH) ExchangeProtocolVersion() (int, error) {
	return s.Writer.Write([]byte("SSH-2.0-GOSSH\r\n"))
}
