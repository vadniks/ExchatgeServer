
package main

import (
    "fmt"
    "github.com/jamesruan/sodium"
)

func main() {
    fmt.Println(sodium.SignSecretKey{Bytes: []byte{1,2,3,4,5,6,7,8}}.Sign(sodium.MakeSignKP().SecretKey)[64:])

    //var waitGroup sync.WaitGroup
    //waitGroup.Add(1)
    //go database.Init(&waitGroup)
    //
    //net.Initialize()
    //net.ProcessClients()
    //
    //waitGroup.Wait()
}
