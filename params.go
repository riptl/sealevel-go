package sealevel

import (
	"bytes"
	"encoding/binary"
)

const ReallocSpace = 1024 * 10
const ReallocAlign = 8

type AccountParam struct {
	IsDuplicate    bool
	DuplicateIndex uint8 // must not be 0xFF
	IsSigner       bool
	IsWritable     bool
	IsExecutable   bool
	Key            [32]byte
	Owner          [32]byte
	Lamports       uint64
	Data           []byte
	RentEpoch      uint64
}

type Params struct {
	Accounts  []AccountParam
	Data      []byte
	ProgramID [32]byte
}

func (p *Params) Serialize(buf *bytes.Buffer) {
	buf.Reset()

	_ = binary.Write(buf, binary.LittleEndian, uint64(len(p.Accounts)))
	for _, account := range p.Accounts {
		if account.IsDuplicate {
			_, _ = buf.Write([]byte{account.DuplicateIndex})
			buf.Grow(7)
		}
		_ = binary.Write(buf, binary.LittleEndian, uint8(0xFF))
		_ = binary.Write(buf, binary.LittleEndian, account.IsSigner)
		_ = binary.Write(buf, binary.LittleEndian, account.IsWritable)
		_ = binary.Write(buf, binary.LittleEndian, account.IsExecutable)
		buf.Grow(4)
		_, _ = buf.Write(account.Key[:])
		_, _ = buf.Write(account.Owner[:])
		_ = binary.Write(buf, binary.LittleEndian, account.Lamports)

		_ = binary.Write(buf, binary.LittleEndian, uint64(len(account.Data)))
		// Copying account :(
		_, _ = buf.Write(account.Data[:])

		buf.Grow(ReallocSpace)
		buf.Grow(1 + ((buf.Len() - 1) / ReallocAlign))

		_ = binary.Write(buf, binary.LittleEndian, account.RentEpoch)
	}

	_ = binary.Write(buf, binary.LittleEndian, uint64(len(p.Data)))
	_, _ = buf.Write(p.Data)

	_, err := buf.Write(p.ProgramID[:])
	if err != nil {
		panic("writes to buffer failed: " + err.Error()) // OOM
	}
}
