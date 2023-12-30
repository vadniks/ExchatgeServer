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

package idsPool

import (
    "ExchatgeServer/utils"
    "math"
    "math/big"
    "sync"
    "unsafe"
)

type IdsPool struct {
    size uint32
    ids big.Int
    mutex sync.Mutex
}

var xFalse, xTrue = func() (byte, byte) { // returns 0, 1 (false, true)
    xFalse := false
    xxFalse := *((*byte) (unsafe.Pointer(&xFalse)))
    utils.Assert(xxFalse == byte(0))

    xTrue := 1
    xxTrue := *((*byte) (unsafe.Pointer(&xTrue)))
    utils.Assert(xxTrue == byte(1))

    return xxFalse, xxTrue
}()

func InitIdsPool(size uint32) *IdsPool { // bitset, aka map[uint32/*id*/]bool/*taken*/
    xIds := &IdsPool{size, big.Int{}, sync.Mutex{}}

    xIds.ids.SetBit(&(xIds.ids), int(size), 1)

    utils.Assert(
        float64(len(xIds.ids.Bytes())) == math.Ceil(float64(size) / float64(8)) &&
        xIds.ids.Bit(0) == uint(xFalse),
    )

    return xIds
}

func (pool *IdsPool) SetId(id uint32, taken bool) {
    pool.mutex.Lock()

    utils.Assert(id < pool.size)
    pool.ids.SetBit(&(pool.ids), int(id), uint(func() byte { if taken { return xTrue } else { return xFalse } }()))

    pool.mutex.Unlock()
}

func (pool *IdsPool) TakeId() *uint32 { // nillable result
    pool.mutex.Lock()

    for i := uint32(0); i < pool.size; i++ {
        if pool.ids.Bit(int(i)) == uint(xFalse) {
            pool.ids.SetBit(&(pool.ids), int(i), uint(xTrue))
            pool.mutex.Unlock()
            return &i
        }
    }

    pool.mutex.Unlock()
    return nil
}

func (pool *IdsPool) ReturnId(id uint32) {
    pool.mutex.Lock()

    utils.Assert(id < pool.size && pool.ids.Bit(int(id)) == uint(xTrue))
    pool.ids.SetBit(&(pool.ids), int(id), uint(xFalse))

    pool.mutex.Unlock()
}
