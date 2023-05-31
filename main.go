
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
    "net"
    "os"
    "unsafe"
)

func errorExit(msg string) {
    fmt.Fprintln(os.Stderr, msg)
    os.Exit(1)
}

func main() {
    server, err := net.Listen("tcp", "localhost:8080")
    if err != nil { errorExit("error listening" + err.Error()) }

    defer server.Close()

    var serverKeys = sodium.MakeKXKP()

    //for {
        // setting connection
        connection, err := server.Accept()
        if err != nil { errorExit("error accepting " + err.Error()) }

        // sending server's public key
        _, err = connection.Write(serverKeys.PublicKey.Bytes)

        // receiving client's public key
        clientPublicKeyBuffer := make([]byte, serverKeys.PublicKey.Size())
        _, err = connection.Read(clientPublicKeyBuffer)
        if err != nil { errorExit("error reading " + err.Error()) }

        // generating session keys
        var clientPublicKey = sodium.KXPublicKey{Bytes: clientPublicKeyBuffer}
        var sessionKeys, err2 = serverKeys.ServerSessionKeys(clientPublicKey)
        if err2 != nil { errorExit("error creating session keys " + err.Error()) }

        fmt.Println(unsafe.Sizeof(*sessionKeys)) // TODO: just to remove 'unused variable' error

        connection.Close()
    //}
}
