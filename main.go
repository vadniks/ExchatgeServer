
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
    "github.com/jamesruan/sodium"
)

func main() {
    skp := sodium.MakeSignKP() // TODO: use hash of a signature of id signing result as a token for verifyin' messages from clients

    msg1 := "test"
    signed := sodium.Bytes(msg1).Sign(skp.SecretKey)
    signedHash := crypto.Hash(signed)

    fmt.Println(len(signed) - len(msg1), []byte(msg1), "\t", signed, "\t", signedHash[:128 - 30]) // 64 bytes for signature

    msg2, err := signed.SignOpen(skp.PublicKey)
    fmt.Println(string(msg2), err)

    fmt.Println(crypto.CompareWithHash(signedHash, signed))

    //var waitGroup sync.WaitGroup
    //waitGroup.Add(1)
    //go database.Init(&waitGroup)
    //
    //net.Initialize()
    //net.ProcessClients()
    //
    //waitGroup.Wait()
}
