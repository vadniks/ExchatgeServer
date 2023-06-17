
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
)

func main() {
    a := crypto.Hash([]byte("test")) // TODO: test only
    b := []byte("test")

    fmt.Println(len(a), a)
    fmt.Println(len(b), b)
    fmt.Println(crypto.CompareWithHash(a, b))

    //database.Init()
    //net.Initialize()
    //net.ProcessClients()
}
