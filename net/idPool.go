
package net

import (
    "ExchatgeServer/utils"
    "math"
    "math/big"
    "unsafe"
)

type idPool struct {
    ids big.Int
}

func initIdPool(size uint32) *idPool { // bitset, aka map[uint32/*id*/]bool/*taken*/
    xFalse, _ := bools()
    xIds := &idPool{big.Int{}}

    xIds.ids.SetBit(&(xIds.ids), int(size), 1)
    utils.Assert(float64(len(xIds.ids.Bytes())) == math.Ceil(float64(size) / float64(8)) && xIds.ids.Bit(0) == uint(xFalse))

    return xIds
}

func bools() (byte, byte) { // returns 0, 1 (false, true)
    xFalse := false
    xxFalse := *((*byte) (unsafe.Pointer(&xFalse)))
    utils.Assert(xxFalse == byte(0))

    xTrue := 1
    xxTrue := *((*byte) (unsafe.Pointer(&xTrue)))
    utils.Assert(xxTrue == byte(1))

    return xxFalse, xxTrue
}

func (pool *idPool) takeId() *uint32 { // nillable result
    xFalse, xTrue := bools()

    for i := uint32(0); i < uint32(maxUsersCount); i++ {
        if pool.ids.Bit(int(i)) == uint(xFalse) {
            pool.ids.SetBit(&(pool.ids), int(i), uint(xTrue))
            return &i
        }
    }
    return nil
}

func (pool *idPool) returnId(id uint32) {
    xFalse, xTrue := bools()
    utils.Assert(id < maxUsersCount && pool.ids.Bit(int(id)) == uint(xTrue))
    pool.ids.SetBit(&(pool.ids), int(id), uint(xFalse))
}
