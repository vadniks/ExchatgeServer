
package main

import (
    "ExchatgeServer/database"
    "ExchatgeServer/net"
    "sync/atomic"
)

func main() {
    var databaseConnected atomic.Bool
    go database.Init(&databaseConnected)

    net.Initialize()
    net.ProcessClients()

    for databaseConnected.Load() {}
}
