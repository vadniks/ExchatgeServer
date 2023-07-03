
package main

import (
    "ExchatgeServer/database"
    "ExchatgeServer/net"
)

func main() {
    database.Init(net.MaxUsersCount)
    net.Initialize()
    net.ProcessClients()
    database.Destroy()
}
