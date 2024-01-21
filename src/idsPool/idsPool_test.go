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

package idsPool

import (
    "math/rand"
    "testing"
)

func TestBasic(t *testing.T) {
    const size = 100
    pool := InitIdsPool(size)

    for i := uint32(0); i < size; i++ {
        j := pool.TakeId()
        if j == nil || i != *j { t.Error() }
    }

    var returned []uint32

    for i := uint32(size / 2); i < size; i++ {
        makeNext:
        next := uint32(rand.Intn(size))

        for _, i := range returned { if next == i { goto makeNext } } // only unique values needed

        pool.ReturnId(next)
        returned = append(returned, next)
    }

    for range returned { if pool.TakeId() == nil { t.Error() } }

    if pool.TakeId() != nil { t.Error() }
}
