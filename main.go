
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
)

func main() {
    fmt.Println(crypto.Hash([]byte("test"))) // TODO: add salt

    //database.Init()
    //net.Initialize()
    //net.ProcessClients()
}
