package core

import (
	"log"
)

func (s *SSH) InitializeConnection() error {
	buf := make([]byte, 1024)
	_, err := s.Reader.Read(buf)

	if err == nil {
		log.Print(string(buf))
	}

	return err
}
