
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
    "github.com/jamesruan/sodium"
    "unsafe"
)

func main() {
    skp := sodium.MakeSignKP() // TODO: use hash of a signature of id signing result as a token for verifyin' messages from clients

    msg1 := "test"
    signed := sodium.Bytes(msg1).Sign(skp.SecretKey)
    signedHash := crypto.Hash(signed)

    fmt.Println(len(signed) - len(msg1), []byte(msg1), "\t", signed, "\t\n", signedHash[:128 - 30]) // 64 bytes for signature

    msg2, err := signed.SignOpen(skp.PublicKey)
    fmt.Println(string(msg2), err)

    fmt.Println(crypto.CompareWithHash(signedHash, signed))

    //

    const danglingSize = 30 // sodium.PWHashStore hash func produces salty-hash with dangling zeroes, cut them off
    id := 1
    idBytes := make([]byte, 4)
    copy(idBytes, unsafe.Slice((*byte) (unsafe.Pointer(&id)), 4))
    signedId := sodium.Bytes(idBytes).Sign(skp.SecretKey) // stays on server
    truncatedHashedSignedId := crypto.Hash(signedId)[:crypto.HashSize - danglingSize] // goes to client as a token (or as a fromId (id of a sender) replacement)

    trueHashedSignedId := make([]byte, crypto.HashSize)
    copy(trueHashedSignedId, truncatedHashedSignedId)
    for i := crypto.HashSize - danglingSize; i < crypto.HashSize; i++ { trueHashedSignedId[i] = 0 }
    fmt.Println("aaa", len(truncatedHashedSignedId), crypto.CompareWithHash(trueHashedSignedId, signedId)) // TODO: 98 bytes for a token

    // TODO: map client connection encryption key with token making it impossible to tamper token imperceptibly to server as both key an token is uniq for each connection

    //var waitGroup sync.WaitGroup
    //waitGroup.Add(1)
    //go database.Init(&waitGroup)
    //
    //net.Initialize()
    //net.ProcessClients()
    //
    //waitGroup.Wait()
}
