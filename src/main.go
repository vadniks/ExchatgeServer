/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023  Vadim Nikolaev (https://github.com/vadniks)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
    "ExchatgeServer/database"
    "ExchatgeServer/net"
    "ExchatgeServer/utils"
    "os"
    "os/exec"
    "strings"
)

func main() {
    println("Exchatge server started...")

    cmd := exec.Command("curl", "-f", "mongodb:27017")
    utils.Assert(cmd.Err == nil)
    out, err := cmd.Output()

    if err != nil || !strings.Contains(string(out), "MongoDB") {
        println("cannot connect to the database, exiting...")
        os.Exit(1)
        return
    }

    database.Init(net.MaxUsersCount)
    println("connected to the database...")

    net.Initialize()
    println("initialized; running")

    net.ProcessClients()

    println("shutting down...")
    database.Destroy()
    println("Exiting now...")
}
