/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023-2024  Vadim Nikolaev (https://github.com/vadniks)
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

package utils

import (
    "os"
    "time"
)

func JustThrow() { panic(any("")) }
func Assert(condition bool) { if !condition { JustThrow() } }
func CurrentTimeMillis() uint64 { return uint64(time.Now().UnixMilli()) }

func MachineId() int64 {
    bytes, err := os.ReadFile("/etc/machine-id")
    if err != nil { return int64(-1) }

    var id int64 = 0
    for _, i := range bytes { id ^= int64(i) }
    return id
}
