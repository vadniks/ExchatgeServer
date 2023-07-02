
package net

import (
    "ExchatgeServer/utils"
    "math"
    "math/big"
    "unsafe"
)

type ids struct {
    bigInt big.Int
}

func initIds(size uint32) *ids { // bitset, aka map[uint32/*id*/]bool/*taken*/
    xFalse, _ := bools()
    xIds := &ids{big.Int{}}

    xIds.bigInt.SetBit(&(xIds.bigInt), int(size), 1)
    utils.Assert(float64(len(xIds.bigInt.Bytes())) == math.Ceil(float64(size) / float64(8)) && xIds.bigInt.Bit(0) == uint(xFalse))

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

func (xIds *ids) takeId() *uint32 { // nillable result
    xFalse, xTrue := bools()

    for i := uint32(0); i < uint32(maxUsersCount); i++ {
        if xIds.bigInt.Bit(int(i)) == uint(xFalse) {
            xIds.bigInt.SetBit(&(xIds.bigInt), int(i), uint(xTrue))
            return &i
        }
    }
    return nil
}

func (xIds *ids) returnId(id uint32) {
    xFalse, xTrue := bools()
    utils.Assert(id < maxUsersCount && xIds.bigInt.Bit(int(id)) == uint(xTrue))
    xIds.bigInt.SetBit(&(xIds.bigInt), int(id), uint(xFalse))
}
