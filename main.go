
package main

import (
    "fmt"
    "net"
    "os"
)

func errorExit(msg string) {
    fmt.Fprintln(os.Stderr, msg)
    os.Exit(1)
}

func main() {
    server, err := net.Listen("tcp", "localhost:8080")
    if err != nil { errorExit("error listening" + err.Error()) }

    defer server.Close()

    for {
        connection, err := server.Accept()
        if err != nil { errorExit("error accepting " + err.Error()) }

        buffer := make([]byte, 256)
        length, err := connection.Read(buffer)

        if err != nil { errorExit("error reading" + err.Error()) }
        fmt.Println(string(buffer[:length]))

        _, err = connection.Write([]byte(" World!"))
        connection.Close()
	}
}
