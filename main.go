
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
)

func main() {
    serverSignPublicKey := []byte{255, 23, 21, 243, 148, 177, 186, 0, 73, 34, 173, 130, 234, 251, 83, 130, 138, 54, 215, 5, 170, 139, 175, 148, 71, 215, 74, 172, 27, 225, 26, 249}
    serverSignSecretKey := []byte{211, 211, 189, 184, 216, 122, 65, 203, 37, 173, 133, 45, 240, 193, 227, 57, 78, 211, 86, 225, 75, 172, 30, 182, 194, 11, 249, 233, 74, 149, 198, 232, 255, 23, 21, 243, 148, 177, 186, 0, 73, 34, 173, 130, 234, 251, 83, 130, 138, 54, 215, 5, 170, 139, 175, 148, 71, 215, 74, 172, 27, 225, 26, 249}

    //skp := sodium.MakeSignKP()
    skp := sodium.SignKP{
       PublicKey: sodium.SignPublicKey{Bytes: serverSignPublicKey}, // goes to clients // TODO: embed public key into client's code
       SecretKey: sodium.SignSecretKey{Bytes: serverSignSecretKey}, // stays on server
    }
    //fmt.Println(skp.PublicKey.Bytes)
    //fmt.Println(skp.SecretKey.Bytes)

    msg1 := "test"
    signed := sodium.Bytes(msg1).Sign(skp.SecretKey)
    fmt.Println(len(signed) - len(msg1), []byte(msg1), signed) // 64 bytes for signature
    msg2, err := signed.SignOpen(skp.PublicKey)
    fmt.Println(string(msg2), err)

    //database.Init()
    //net.Initialize()
    //net.ProcessClients()
}
