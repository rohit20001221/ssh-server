package core

import "log"

func (s *SSH) InitKeyExchange() error {
	packet, err := s.Read()
	if err != nil {
		return err
	}

	log.Println(packet)

	return nil
}
