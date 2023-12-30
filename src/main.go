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
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"
)

const databaseAvailabilityCheckMaxTries = 10 // at most 10 seconds timeout

func checkDatabaseAvailability(url string) bool {
    cmd := exec.Command("curl", "-f", url)
    utils.Assert(cmd.Err == nil)

    out, err := cmd.Output()
    return err == nil && strings.Contains(string(out), "MongoDB")
}

////////////////////////////////////////////////////////////////////////////////
// REMEMBER TO DISABLE THAT F*** GoFMT IN IDE'S SETTINGS! HIS STYLE IS AWFUL! //
////////////////////////////////////////////////////////////////////////////////

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

    counter := 0
    for !checkDatabaseAvailability(strings.Split(xOptions.MongodbUrl, "@")[1]) {
        if counter >= databaseAvailabilityCheckMaxTries {
            println("timeout exceeded, exiting...")
            os.Exit(1)
            return
        } else {
            fmt.Printf("waiting for the database to become available (%d/%d)...\n", counter, databaseAvailabilityCheckMaxTries)
        }

        counter++
        time.Sleep(1e+9) // 1 second = 1000 milliseconds = 1 000 000 000 nanoseconds
    }

    crypto.Initialize(xOptions.ServerPrivateSignKey)

    database.Initialize(uint32(xOptions.MaxUsersCount), xOptions.MongodbUrl, xOptions.AdminPassword)
    println("connected to the database...")

    net.Initialize(xOptions.MaxUsersCount, xOptions.MaxTimeMillisToPreserveActiveConnection, xOptions.MaxTimeMillisIntervalBetweenMessages)
    println("initialized; running")

    net.ProcessClients(xOptions.Host, xOptions.Port)

    println("shutting down...")
    database.Destroy()
    println("Exiting now...")
}
