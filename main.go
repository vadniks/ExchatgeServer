
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
    "net"
)

func main() {
    nonce := sodium.SecretBoxNonce{} // TODO: test only
    sodium.Randomize(&nonce)

    key := sodium.Bytes("12345678") // TODO: test only
    length := len(key)
    for i := length; i < 32; i++ { key = append(key, 0) }

    //encrypted := sodium.Bytes("Encrypted").SecretBox(nonce, sodium.SecretBoxKey{Bytes: key}) // TODO: test only
    //fmt.Println(len(encrypted))

    cryptState := newCryptoState(16, 1048) // TODO: test only
    padded := cryptState._addPadding(make([]byte, 1048))
    fmt.Println(len(padded))
    for _, j := range padded { fmt.Printf("%d ", j) }
    fmt.Println()

    unpadded := cryptState._removePadding(padded) // TODO: test only
    fmt.Println(len(unpadded))
    for _, j := range unpadded { fmt.Printf("%d ", j) }
    fmt.Println() // TODO: works

    msg := []byte("Test") // TODO: test only
    for i := len(msg); i < int(cryptState._paddedSize); i++ { msg = append(msg, 0) }
    fmt.Println("bb")
    for _, j := range msg { fmt.Printf("%d ", j) }
    fmt.Println()

    fmt.Println("aa ", len(msg)) // TODO: test only
    encrypted := cryptState._encrypt(msg)
    fmt.Println(len(encrypted))
    for _, j := range encrypted { fmt.Printf("%d ", j) }
    fmt.Println()

    decrypted := cryptState._decrypt(encrypted) // TODO: test only
    fmt.Println("d", len(decrypted))
    for _, j := range decrypted { fmt.Printf("%d ", j) }
    fmt.Println() // TODO: works properly

    return // TODO: test only

    //msg := Message{ // TODO: test only
    //    flag:      0x7fffffff,
    //    timestamp: 0,
    //    size:      _MessageBodySize,
    //    index:     0,
    //    count:     1,
    //    body:      [_MessageBodySize]byte{},
    //}
    //for i, j := range "Test connection" { msg.body[i] = byte(j) }
    //
    //packed := msg._pack() // TODO: test only
    //for _, i := range packed { fmt.Printf("%d ", i) }
    //fmt.Println()
    //unpacked := _unpackMessage(packed)
    //fmt.Println(unpacked.flag, unpacked.timestamp, unpacked.size, unpacked.index, unpacked.count, string(unpacked.body[:]))
    ////return // TODO: _pack also works
    //
    //server, err := net.Listen("tcp", "localhost:8080")
    //if err != nil { throw("error listening" + err.Error()) }
    //
    //defer server.Close()
    //
    //var serverKeys = sodium.MakeKXKP()
    //
    ////for { // The only loop that exists in this language is the for loop - seriously? where the f*** is the wile loop?
    //    connection, err := server.Accept()
    //    if err != nil { throw("error accepting " + err.Error()) }
    //    /*go*/ processClient(connection, serverKeys)
    ////}
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
    clientMessageBuffer := make([]byte, _MessageSize)
    var n = 0
    for n == 0 { n, err = connection.Read(clientMessageBuffer)}
    for _, i := range clientMessageBuffer { fmt.Printf("%d ", i) }
    fmt.Println()
    msg := _unpackMessage(clientMessageBuffer)
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
