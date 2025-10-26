package core

import (
	"io"
	"log"
)

func InitializeConnection(reader io.Reader) error {
	buf := make([]byte, 1024)
	_, err := reader.Read(buf)

	if err == nil {
		log.Print(string(buf))
	}

	return err
}
