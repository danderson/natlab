package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
)

func NewRandom() *rand.Rand {
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err != nil {
		panic("ran out of entropy")
	}
	return rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(buf[:]))))
}
