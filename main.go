
package main

import (
    "ExchatgeServer/net"
    "fmt"
)

func main() {
    fmt.Println(*net.TakeId())
    fmt.Println(*net.TakeId())
    fmt.Println(*net.TakeId(), "a")
    for i := 0; i < 100; i++ { fmt.Println(*net.TakeId(), i) }
    net.ReturnId(1)
    net.ReturnId(2)
    net.ReturnId(0)
    //database.Init()
    //net.Initialize()
    //net.ProcessClients()
    //database.Destroy()
}
