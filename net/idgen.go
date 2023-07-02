
package net

import (
    "ExchatgeServer/utils"
    "math"
    "math/big"
    "unsafe"
)

var ids = func () *big.Int { // bitset, aka map[uint32/*id*/]bool/*taken*/
    xFalse, _ := bools()
    xIds := new(big.Int)

    xIds.SetBit(xIds, maxUsersCount, 1)
    utils.Assert(float64(len(xIds.Bytes())) == math.Ceil(float64(maxUsersCount) / float64(8)) && xIds.Bit(0) == uint(xFalse))

    return xIds
}()

func bools() (byte, byte) { // returns 0, 1 (false, true)
    xFalse := false
    xxFalse := *((*byte) (unsafe.Pointer(&xFalse)))
    utils.Assert(xxFalse == byte(0))

    xTrue := 1
    xxTrue := *((*byte) (unsafe.Pointer(&xTrue)))
    utils.Assert(xxTrue == byte(1))

    return xxFalse, xxTrue
}

func takeId() *uint32 { // nillable result
    xFalse, xTrue := bools()

    for i := uint32(0); i < uint32(maxUsersCount); i++ {
        if ids.Bit(int(i)) == uint(xFalse) { // if the id hasn't been taken
            ids.SetBit(ids, int(i), uint(xTrue)) // take it
            return &i
        }
    }
    return nil
}

func returnId(id uint32) {
    xFalse, xTrue := bools()
    utils.Assert(id < maxUsersCount && ids.Bit(int(id)) == uint(xTrue))
    ids.SetBit(ids, int(id), uint(xFalse))
}
