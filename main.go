
package main

import (
    "ExchatgeServer/database"
    "ExchatgeServer/net"
    "sync"
)

func main() {
    var waitGroup sync.WaitGroup
    waitGroup.Add(1)
    go database.Init(&waitGroup)

    net.Initialize()
    net.ProcessClients()

    waitGroup.Wait()
}
