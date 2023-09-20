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
    "ExchatgeServer/crypto"
    "ExchatgeServer/database"
    "ExchatgeServer/net"
    "ExchatgeServer/options"
    "ExchatgeServer/utils"
    "os"
    "os/exec"
    "strings"
)

func main() {
    print("\033[1;32m" +
    "_______ _     _ _______ _     _ _______ _______  ______ _______\n" +
    "|______  \\___/  |       |_____| |_____|    |    |  ____ |______\n" +
    "|______ _/   \\_ |_____  |     | |     |    |    |_____| |______\n" +
    "                   free software (GNU GPL v3)                   \033[0m\n")

    println("Exchatge server started...")

    xOptions := options.Init(crypto.SecretKeySize, net.UnhashedPasswordSize)
    if xOptions == nil {
        println("unable to parse options, exiting...")
        os.Exit(1)
        return
    }

    cmd := exec.Command("curl", "-f", strings.Split(xOptions.MongodbUrl, "@")[1])
    utils.Assert(cmd.Err == nil)
    out, err := cmd.Output()

    if err != nil || !strings.Contains(string(out), "MongoDB") {
        println("cannot connect to the database, exiting...")
        os.Exit(1)
        return
    }

    crypto.Initialize(xOptions.ServerPrivateSignKey)

    database.Initialize(uint32(xOptions.MaxUsersCount), xOptions.MongodbUrl, xOptions.AdminPassword)
    println("connected to the database...")

    net.Initialize(xOptions.MaxUsersCount)
    println("initialized; running")

    net.ProcessClients(xOptions.Host, xOptions.Port)

    println("shutting down...")
    database.Destroy()
    println("Exiting now...")
}
