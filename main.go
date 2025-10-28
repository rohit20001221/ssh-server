package main

import (
	"bufio"
	"log"
	"net"

	"ssh.com/core"
)

func main() {
	ln, err := net.Listen("tcp", ":4444")
	if err != nil {
		log.Fatalln("[x] error:", err)
	}

	for {
		conn, err := ln.Accept()

		if err != nil {
			log.Println("[x] error:", err)
		} else {
			go func() {
				defer conn.Close()

				reader := bufio.NewReader(conn)
				writer := conn

				for {
					if err := core.InitializeConnection(reader); err != nil {
						log.Println("[x] error:", err)
						break
					}

					if _, err := core.ExchangeProtocolVersion(writer); err != nil {
						log.Println("[x] error:", err)
						break
					}

					if err := core.InitKeyExchange(reader, conn); err != nil {
						log.Println("[x] error:", err)
						break
					}

					data := make([]byte, 35000)
					reader.Read(data)

					log.Println(string(data))

					/* Loop to Read commands from the user */
					ch := make(chan string)
					<-ch
				}
			}()
		}
	}
}
