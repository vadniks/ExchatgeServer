
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
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

        // trying to read client's message
        clientMessageBuffer := make([]byte, 12)
        var n = 0
        for n == 0 { n, err = connection.Read(clientMessageBuffer)}
        fmt.Println("a ", string(clientMessageBuffer))

        fmt.Println("rx:")
        for _, i := range sessionKeys.Rx.Bytes { fmt.Printf("%d ", i) }
        fmt.Println("\ntx:")
        for _, i := range sessionKeys.Tx.Bytes { fmt.Printf("%d ", i) }

        // trying to decrypt the message
        //decrypted, err := sodium.Bytes(clientMessageBuffer).BoxOpen(
        //    sodium.BoxNonce{Bytes: sodium.Bytes("123456789012345678901234")},
        //    sodium.BoxPublicKey(sessionKeys.Rx),
        //    sodium.BoxSecretKey(sessionKeys.Tx),
        //)
        //if err != nil { errorExit("error decrypting the message " + err.Error()) }
        //
        //fmt.Println("b ", string(decrypted))

        connection.Close()
    //}
}
