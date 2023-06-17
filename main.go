
package main

import (
    "ExchatgeServer/crypto"
    "fmt"
)

func main() {
    token := crypto.Tokenize(1)
    fmt.Println(*(crypto.Untokenize(token)), token) // TODO: add token

    //var waitGroup sync.WaitGroup
    //waitGroup.Add(1)
    //go database.Init(&waitGroup)
    //
    //net.Initialize()
    //net.ProcessClients()
    //
    //waitGroup.Wait()
}
