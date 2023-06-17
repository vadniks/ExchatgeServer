
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
)

func main() {
    id := uint32(1)
    reference, token := crypto.Tokenize(id)
    fmt.Println("aaa", crypto.CompareToken(reference, token))

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
