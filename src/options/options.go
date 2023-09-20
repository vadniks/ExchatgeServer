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

type optionsT struct {
    host string
    port uint
    maxUsersCount uint
    serverPrivateSignKey []byte
    mongodbUrl string
    adminPassword []byte
}

func Init() bool { // nillable // TODO: replace nillable values with self-made optionals
    bytes, err := os.ReadFile(fileName)
    if len(bytes) == 0 || err != nil { return false }

    lines := strings.Split(string(bytes), string('\n'))
    if len(lines) != linesCount { return false }

    parseHost(lines[0])

    return true
}

func parseHost(text string) (string, bool) {

    return "", false
}
