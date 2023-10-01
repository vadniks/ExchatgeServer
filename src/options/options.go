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

package options

import (
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

const (
    fileName = "options.txt"
    host = "host"
    port = "port"
    maxUsersCount = "maxUsersCount"
    serverPrivateSignKey = "serverPrivateSignKey"
    mongodbUrl = "mongodbUrl"
    adminPassword = "adminPassword"
    linesCount = 6
)

type Options struct {
    Host string
    Port uint
    MaxUsersCount uint
    ServerPrivateSignKey []byte
    MongodbUrl string
    AdminPassword []byte // TODO: fill with random bytes after use
}

func Init(secretKeySize uint, maxPasswordSize uint) *Options { // nillable // TODO: replace nillable values with self-made optionals
    exe, _ := os.Executable()

    bytes, err := os.ReadFile(filepath.Dir(exe) + "/" + fileName)
    if len(bytes) == 0 || err != nil { return nil }

    lines := strings.Split(string(bytes), "\n")
    if len(lines) != linesCount { return nil }

    options := &Options{
        Host: "",
        Port: 0,
        MaxUsersCount: 0,
        ServerPrivateSignKey: nil,
        MongodbUrl: "",
        AdminPassword: nil,
    }

    for _, line := range lines {
        parts := strings.Split(line, "=")
        value := parts[1]

        switch parts[0] {
            case host:
                options.Host = parseHost(value)
                if len(options.Host) == 0 { return nil }
            case port:
                options.Port = parsePort(value)
                if options.Port == 0 { return nil }
            case maxUsersCount:
                options.MaxUsersCount = parseMaxUsersCount(value)
                if options.MaxUsersCount == 0 { return nil }
            case serverPrivateSignKey:
                options.ServerPrivateSignKey = parseServerPrivateSignKey(value, secretKeySize)
                if len(options.ServerPrivateSignKey) == 0 { return nil }
            case mongodbUrl:
                options.MongodbUrl = parseMongodbUrl(value)
                if len(options.MongodbUrl) == 0 { return nil }
            case adminPassword:
                options.AdminPassword = parseAdminPassword(value, maxPasswordSize)
                if len(options.AdminPassword) == 0 { return nil }
        }
    }

    return options
}

func parseHost(value string) string { return value }

func parseUint(str string) uint {
    xInt, err := strconv.Atoi(str)
    if err != nil || xInt < 0 { return 0 }
    return uint(xInt)
}

func parsePort(value string) uint { return parseUint(value) }

func parseMaxUsersCount(value string) uint {
    count := parseUint(value)

    if count > 1 << 14 {
        return 0
    } else {
        return count
    }
}

func parseServerPrivateSignKey(value string, secretKeySize uint) []byte { // nillable
    bytes := make([]byte, secretKeySize)

    count := 0
    for index, number := range strings.Split(value, ",") {
        bytes[index] = byte(parseUint(number))
        count++
    }

    if uint(count) != secretKeySize {
        return nil
    } else {
        return bytes
    }
}

func parseMongodbUrl(value string) string { return value }

func parseAdminPassword(value string, maxPasswordSize uint) []byte { // nillable
    bytes := make([]byte, maxPasswordSize)

    var count uint = 0
    for index, char := range value {
        bytes[index] = byte(char)
        count++
    }

    if count > maxPasswordSize || count == 0 {
        return nil
    } else {
        return bytes
    }
}
