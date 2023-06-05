
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
    "net"
)

func main() {
    msg := Message{ // TODO: test only
        flag: 0x7fffffff,
        timestamp: 0,
        size: MessageBodySize,
        index: 0,
        count: 1,
        body: [MessageBodySize]byte{},
    }
    for i, j := range "Test connection" { msg.body[i] = byte(j) }

    packed := msg.pack() // TODO: test only
    for _, i := range packed { fmt.Printf("%d ", i) }
    fmt.Println()
    unpacked := unpackMessage(packed)
    fmt.Println(unpacked.flag, unpacked.timestamp, unpacked.size, unpacked.index, unpacked.count, string(unpacked.body[:]))
    //return // TODO: pack also works

    server, err := net.Listen("tcp", "localhost:8080")
    if err != nil { throw("error listening" + err.Error()) }

    defer server.Close()

    var serverKeys = sodium.MakeKXKP()

    //for { // The only loop that exists in this language is the for loop - seriously? where the f*** is the wile loop?
        connection, err := server.Accept()
        if err != nil { throw("error accepting " + err.Error()) }
        /*go*/ processClient(connection, serverKeys)
    //}
}

func processClient(connection net.Conn, serverKeys sodium.KXKP) {
    // sending server's public key
    _, err := connection.Write(serverKeys.PublicKey.Bytes)
    if err != nil { throw("error sending public key " + err.Error()) }

    // receiving client's public key
    clientPublicKeyBuffer := make([]byte, serverKeys.PublicKey.Size())
    _, err = connection.Read(clientPublicKeyBuffer)
    if err != nil { throw("error reading " + err.Error()) }

    // generating session keys
    var clientPublicKey = sodium.KXPublicKey{Bytes: clientPublicKeyBuffer}
    var _/*sessionKeys*/, err2 = serverKeys.ServerSessionKeys(clientPublicKey)
    if err2 != nil { throw("error creating session keys " + err.Error()) }

    // trying to read client's message
    clientMessageBuffer := make([]byte, MessageSize)
    var n = 0
    for n == 0 { n, err = connection.Read(clientMessageBuffer)}
    for _, i := range clientMessageBuffer { fmt.Printf("%d ", i) }
    fmt.Println()
    msg := unpackMessage(clientMessageBuffer)
    fmt.Println(msg.flag, msg.timestamp, msg.size, msg.index, msg.count, string(msg.body[:])) // TODO: unpack works

    //fmt.Println("rx:") // TODO: test only
    //for _, i := range sessionKeys.Rx.Bytes { fmt.Printf("%d ", i) }
    //fmt.Println("\ntx:")
    //for _, i := range sessionKeys.Tx.Bytes { fmt.Printf("%d ", i) }

    // trying to decrypt the message // TODO: crypto_secretbox_*()
    //decrypted, err := sodium.Bytes(clientMessageBuffer).BoxOpen(
    //    sodium.BoxNonce{Bytes: sodium.Bytes("123456789012345678901234")},
    //    sodium.BoxPublicKey(sessionKeys.Rx),
    //    sodium.BoxSecretKey(sessionKeys.Tx),
    //)
    //if err != nil { errorExit("error decrypting the message " + err.Error()) }
    //
    //fmt.Println("b ", string(decrypted))

    connection.Close()
}
