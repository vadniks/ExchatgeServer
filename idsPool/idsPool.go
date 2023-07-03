
package idsPool

import (
    "ExchatgeServer/utils"
    "math"
    "math/big"
    "unsafe"
)

type IdsPool struct {
    size uint32
    ids big.Int
}

func InitIdsPool(size uint32) *IdsPool { // bitset, aka map[uint32/*id*/]bool/*taken*/
    xFalse, _ := bools()
    xIds := &IdsPool{size, big.Int{}}

    xIds.ids.SetBit(&(xIds.ids), int(size), 1)

    utils.Assert(
        float64(len(xIds.ids.Bytes())) == math.Ceil(float64(size) / float64(8)) &&
        xIds.ids.Bit(0) == uint(xFalse),
    )

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

func (pool *IdsPool) SetId(id uint32, taken bool) {
    xFalse, xTrue := bools()
    utils.Assert(id < pool.size)
    pool.ids.SetBit(&(pool.ids), int(id), uint(func() byte { if taken { return xTrue } else { return xFalse } }()))
}

func (pool *IdsPool) TakeId() *uint32 { // nillable result
    xFalse, xTrue := bools()

    for i := uint32(0); i < pool.size; i++ {
        if pool.ids.Bit(int(i)) == uint(xFalse) {
            pool.ids.SetBit(&(pool.ids), int(i), uint(xTrue))
            return &i
        }
    }
    return nil
}

func (pool *IdsPool) ReturnId(id uint32) {
    xFalse, xTrue := bools()
    utils.Assert(id < pool.size && pool.ids.Bit(int(id)) == uint(xTrue))
    pool.ids.SetBit(&(pool.ids), int(id), uint(xFalse))
}
