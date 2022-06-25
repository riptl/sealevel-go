// Copyright 2022 Richard Patel (@terorie)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sealevel

import (
	"bytes"
	"embed"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed minimal.solana.so
var minimalELF []byte

func TestExecute_Simple(t *testing.T) {
	opts := NewConfigOpts()
	opts.EnableInsnMeter = true
	config := NewConfig(opts)
	syscalls := NewSyscallRegistry()

	// Load addition program
	program, err := LoadProgram(config, syscalls, minimalELF)
	require.NoError(t, err, "failed to load program")

	a, b := 1, 3

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint64(a))
	_ = binary.Write(&buf, binary.LittleEndian, uint64(b))
	vm, err := NewVM(program, nil, []Region{
		{
			Data:      buf.Bytes(),
			VMAddr:    0x4_0000_0000,
			VMGapSize: 0,
			Writable:  false,
		},
	})
	require.NoError(t, err, "failed to create VM")

	r0, err := vm.Execute()
	require.NoError(t, err, "execution failed")

	assert.Equal(t, uint64(4), r0)
}

func TestError(t *testing.T) {
	config := NewConfig(nil)
	syscalls := NewSyscallRegistry()

	const errMsg = "ElfError(FailedToParse(\"read-write: bad offset 0\"))"
	program, err := LoadProgram(config, syscalls, nil)
	require.Equal(t, Error{
		Code:    ErrInvalidElf,
		Message: errMsg,
	}, err)
	require.EqualError(t, err, errMsg)
	require.Nil(t, program)
	runtime.GC()
}

var _ embed.FS // GoLand is being a bitch and optimizing away the embed import
