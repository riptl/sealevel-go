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

// Package sealevel interfaces with SBF runtime of the Solana Rust implementation.
package sealevel

// #cgo LDFLAGS: -lsealevel
// #include <sealevel.h>
import "C"

import (
	"runtime"
	"unsafe"
)

// used to hint to linter that copies are illegal ©
type noCopy struct{}

// Config wraps solana_rbpf::vm::Config.
// Must not be copied after first use.
type Config struct {
	config *C.sealevel_config
	noCopy
}

func (c *Config) free() {
	C.sealevel_config_free(c.config)
}

// NewConfig creates a new config object based on the given options.
//
// Calls `sealevel_config_new` and sets it up using `sealevel_config_setopt`.
func NewConfig(opts *ConfigOpts) *Config {
	config := C.sealevel_config_new()
	wrapper := new(Config)
	wrapper.config = config
	runtime.SetFinalizer(wrapper, (*Config).free)
	if opts != nil {
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_NO_VERIFY, bool2size(opts.NoVerify))
		if opts.MaxCallDepth == 0 {
			opts.MaxCallDepth = 20
		}
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_MAX_CALL_DEPTH, C.size_t(opts.MaxCallDepth))
		if opts.StackFrameSize == 0 {
			opts.StackFrameSize = 4096
		}
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_STACK_FRAME_SIZE, C.size_t(opts.StackFrameSize))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_STACK_FRAME_GAPS, bool2size(opts.EnableStackFrameGaps))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_INSTRUCTION_METER_CHECKPOINT_DISTANCE, C.size_t(opts.InsnMeterCheckpointDist))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_INSTRUCTION_METER, bool2size(opts.EnableInsnMeter))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_INSTRUCTION_TRACING, bool2size(opts.EnableInsnTracing))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_SYMBOL_AND_SECTION_LABELS, bool2size(opts.EnableSymbolAndSectionLabels))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_DISABLE_UNRESOLVED_SYMBOLS_AT_RUNTIME, bool2size(opts.DisableUnresolvedSymsAtRuntime))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_REJECT_BROKEN_ELFS, bool2size(opts.RejectBrokenELFs))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_NOOP_INSTRUCTION_RATIO, C.size_t(opts.NoopInsnRate))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_SANITIZE_USER_PROVIDED_VALUES, bool2size(opts.SanitizeUserProvidedValues))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENCRYPT_ENVIRONMENT_REGISTERS, bool2size(opts.EncryptEnvRegisters))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_DISABLE_DEPRECATED_LOAD_INSTRUCTIONS, bool2size(opts.DisableDeprecatedLoadInsns))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_SYSCALL_BPF_FUNCTION_HASH_COLLISION, bool2size(opts.SyscallBPFFuncHashColission))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_REJECT_CALLX_R10, bool2size(opts.RejectCallxR10))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_DYNAMIC_STACK_FRAMES, bool2size(opts.DynamicStackFrames))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_SDIV, bool2size(opts.EnableSdiv))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_OPTIMIZE_RODATA, bool2size(opts.OptimizeRodata))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_STATIC_SYSCALLS, bool2size(opts.StaticSyscalls))
		C.sealevel_config_setopt(config, C.SEALEVEL_OPT_ENABLE_ELF_VADDR, bool2size(opts.EnableELFVaddr))
	}
	return wrapper
}

func bool2size(b bool) C.size_t {
	if b {
		return 1
	} else {
		return 0
	}
}

type SyscallID int

// Syscall IDs
const (
	SyscallID_Invalid                           = SyscallID(C.SEALEVEL_SYSCALL_INVALID)
	SyscallID_Abort                             = SyscallID(C.SEALEVEL_SYSCALL_ABORT)
	SyscallID_SolPanic                          = SyscallID(C.SEALEVEL_SYSCALL_SOL_PANIC)
	SyscallID_SolLog                            = SyscallID(C.SEALEVEL_SYSCALL_SOL_LOG)
	SyscallID_SolLog64                          = SyscallID(C.SEALEVEL_SYSCALL_SOL_LOG_64)
	SyscallID_SolLogComputeUnits                = SyscallID(C.SEALEVEL_SYSCALL_SOL_LOG_COMPUTE_UNITS)
	SyscallID_SolLogPubkey                      = SyscallID(C.SEALEVEL_SYSCALL_SOL_LOG_PUBKEY)
	SyscallID_SolCreateProgramAddress           = SyscallID(C.SEALEVEL_SYSCALL_SOL_CREATE_PROGRAM_ADDRESS)
	SyscallID_SolTryFindProgramAddress          = SyscallID(C.SEALEVEL_SYSCALL_SOL_TRY_FIND_PROGRAM_ADDRESS)
	SyscallID_SolSha256                         = SyscallID(C.SEALEVEL_SYSCALL_SOL_SHA256)
	SyscallID_SolKeccak256                      = SyscallID(C.SEALEVEL_SYSCALL_SOL_KECCAK256)
	SyscallID_SolSecp256K1Recover               = SyscallID(C.SEALEVEL_SYSCALL_SOL_SECP256K1_RECOVER)
	SyscallID_SolBlake3                         = SyscallID(C.SEALEVEL_SYSCALL_SOL_BLAKE3)
	SyscallID_SolZkTokenElgamalOp               = SyscallID(C.SEALEVEL_SYSCALL_SOL_ZK_TOKEN_ELGAMAL_OP)
	SyscallID_SolZkTokenElgamalOpWithLoHi       = SyscallID(C.SEALEVEL_SYSCALL_SOL_ZK_TOKEN_ELGAMAL_OP_WITH_LO_HI)
	SyscallID_SolZkTokenElgamalOpWithScalar     = SyscallID(C.SEALEVEL_SYSCALL_SOL_ZK_TOKEN_ELGAMAL_OP_WITH_SCALAR)
	SyscallID_SolCurveValidatePoint             = SyscallID(C.SEALEVEL_SYSCALL_SOL_CURVE_VALIDATE_POINT)
	SyscallID_SolCurveGroupOp                   = SyscallID(C.SEALEVEL_SYSCALL_SOL_CURVE_GROUP_OP)
	SyscallID_SolGetClockSysvar                 = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_CLOCK_SYSVAR)
	SyscallID_SolGetEpochScheduleSysvar         = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_EPOCH_SCHEDULE_SYSVAR)
	SyscallID_SolGetFeesSysvar                  = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_FEES_SYSVAR)
	SyscallID_SolGetRentSysvar                  = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_RENT_SYSVAR)
	SyscallID_SolMemcpy                         = SyscallID(C.SEALEVEL_SYSCALL_SOL_MEMCPY)
	SyscallID_SolMemmove                        = SyscallID(C.SEALEVEL_SYSCALL_SOL_MEMMOVE)
	SyscallID_SolMemcmp                         = SyscallID(C.SEALEVEL_SYSCALL_SOL_MEMCMP)
	SyscallID_SolMemset                         = SyscallID(C.SEALEVEL_SYSCALL_SOL_MEMSET)
	SyscallID_SolInvokeSignedC                  = SyscallID(C.SEALEVEL_SYSCALL_SOL_INVOKE_SIGNED_C)
	SyscallID_SolInvokeSignedRust               = SyscallID(C.SEALEVEL_SYSCALL_SOL_INVOKE_SIGNED_RUST)
	SyscallID_SolAllocFree                      = SyscallID(C.SEALEVEL_SYSCALL_SOL_ALLOC_FREE)
	SyscallID_SolSetReturnData                  = SyscallID(C.SEALEVEL_SYSCALL_SOL_SET_RETURN_DATA)
	SyscallID_SolGetReturnData                  = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_RETURN_DATA)
	SyscallID_SolLogData                        = SyscallID(C.SEALEVEL_SYSCALL_SOL_LOG_DATA)
	SyscallID_SolGetProcessedSiblingInstruction = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_PROCESSED_SIBLING_INSTRUCTION)
	SyscallID_SolGetStackHeight                 = SyscallID(C.SEALEVEL_SYSCALL_SOL_GET_STACK_HEIGHT)
)

// SyscallRegistry wraps solana_rbpf::vm::SyscallRegistry.
type SyscallRegistry struct {
	inner C.sealevel_syscall_registry
}

// NewSyscallRegistry wraps `sealevel_syscall_registry_new`.
func NewSyscallRegistry() *SyscallRegistry {
	registry := C.sealevel_syscall_registry_new()
	wrapper := new(SyscallRegistry)
	wrapper.inner = registry
	runtime.SetFinalizer(wrapper, (*SyscallRegistry).free)
	return wrapper
}

func (s *SyscallRegistry) free() {
	C.sealevel_syscall_registry_free(s.inner)
}

type ErrCode uint

// Error codes (enum branches of solana_rbpf::error::EbpfError)
const (
	ErrUnknown                 = ErrCode(C.SEALEVEL_ERR_UNKNOWN)
	Ok                         = ErrCode(C.SEALEVEL_OK)
	ErrInvalidElf              = ErrCode(C.SEALEVEL_ERR_INVALID_ELF)
	ErrSyscallRegistration     = ErrCode(C.SEALEVEL_ERR_SYSCALL_REGISTRATION)
	ErrCallDepthExceeded       = ErrCode(C.SEALEVEL_ERR_CALL_DEPTH_EXCEEDED)
	ErrExitRootCallFrame       = ErrCode(C.SEALEVEL_ERR_EXIT_ROOT_CALL_FRAME)
	ErrDivideByZero            = ErrCode(C.SEALEVEL_ERR_DIVIDE_BY_ZERO)
	ErrDivideOverflow          = ErrCode(C.SEALEVEL_ERR_DIVIDE_OVERFLOW)
	ErrExecutionOverrun        = ErrCode(C.SEALEVEL_ERR_EXECUTION_OVERRUN)
	ErrCallOutsideTextSegment  = ErrCode(C.SEALEVEL_ERR_CALL_OUTSIDE_TEXT_SEGMENT)
	ErrExceededMaxInstructions = ErrCode(C.SEALEVEL_ERR_EXCEEDED_MAX_INSTRUCTIONS)
	ErrJitNotCompiled          = ErrCode(C.SEALEVEL_ERR_JIT_NOT_COMPILED)
	ErrInvalidVirtualAddress   = ErrCode(C.SEALEVEL_ERR_INVALID_VIRTUAL_ADDRESS)
	ErrInvalidMemoryRegion     = ErrCode(C.SEALEVEL_ERR_INVALID_MEMORY_REGION)
	ErrAccessViolation         = ErrCode(C.SEALEVEL_ERR_ACCESS_VIOLATION)
	ErrStackAccessViolation    = ErrCode(C.SEALEVEL_ERR_STACK_ACCESS_VIOLATION)
	ErrInvalidInstruction      = ErrCode(C.SEALEVEL_ERR_INVALID_INSTRUCTION)
	ErrUnsupportedInstruction  = ErrCode(C.SEALEVEL_ERR_UNSUPPORTED_INSTRUCTION)
	ErrErrExhaustedTextSegment = ErrCode(C.SEALEVEL_ERR_ERR_EXHAUSTED_TEXT_SEGMENT)
	ErrLibcInvocationFailed    = ErrCode(C.SEALEVEL_ERR_LIBC_INVOCATION_FAILED)
	ErrVerifierError           = ErrCode(C.SEALEVEL_ERR_VERIFIER_ERROR)
)

// RegisterBuiltin registers a builtin Solana syscall with the registry.
func (s *SyscallRegistry) RegisterBuiltin(id SyscallID) bool {
	return C.sealevel_syscall_register_builtin(s.inner, id)
}

// Error maps to solana_rbpf::error::EbpfError.
type Error struct {
	Code    ErrCode
	Message string
}

// Returns the current thread-local error.
func currentError() error {
	errno := ErrCode(C.sealevel_errno())
	if errno == Ok {
		return nil
	}
	return Error{
		Code:    errno,
		Message: C.GoString(C.sealevel_strerror()),
	}
}

// Error returns the message from `sealevel_strerror`.
func (e Error) Error() string {
	return e.Message
}

// Executable wraps `solana_rbpf::vm::VerifiedExecutable`.
type Executable struct {
	program *C.sealevel_executable
	used    bool
	noCopy
}

/*
func (e *Executable) free() {
	if !e.used {
		// TODO destroy program
	}
}
*/

// LoadProgram wraps `sealevel_load_program`.
func LoadProgram(config *Config, syscalls *SyscallRegistry, elf []byte) (*Executable, error) {
	var elfPtr *C.char
	if len(elf) > 0 {
		// only borrowed, no copy needed … i think?
		elfPtr = (*C.char)(unsafe.Pointer(&elf[0]))
	}

	program := C.sealevel_load_program(
		config.config,
		syscalls.inner,
		elfPtr,
		(C.size_t)(len(elf)),
	)
	if program == nil {
		return nil, currentError()
	}
	exec := new(Executable)
	*exec = Executable{
		program: program,
		used:    false,
	}
	//runtime.SetFinalizer(exec, (*Executable).free)
	return exec, nil
}

// Compile JIT compiles the executable via `sealevel_program_jit_compile`.
// Internally calls `solana_rbpf::vm::Executable::jit_compile`.
func (e *Executable) Compile() {
	if !e.used {
		C.sealevel_program_jit_compile(e.program)
	}
}

// Region maps to struct `sealevel_region`.
// Internally maps to `solana_rbpf::memory_region::MemoryRegion`.
type Region struct {
	Data       []byte
	VMAddr     uint64
	VMGapSize  uint64
	IsWritable bool
}

func (r Region) ffi() C.sealevel_region {
	return C.sealevel_region{
		data_addr:   C.CBytes(r.Data), // copy :(
		data_size:   C.size_t(len(r.Data)),
		vm_addr:     C.uint64_t(r.VMAddr),
		vm_gap_size: C.uint64_t(r.VMGapSize),
		is_writable: C.bool(r.IsWritable),
	}
}

// VM wraps struct `sealevel_vm`.
type VM struct {
	vm       *C.sealevel_vm
	heap     unsafe.Pointer
	dataPtrs []unsafe.Pointer
	noCopy
}

func (v *VM) free() {
	C.sealevel_vm_destroy(v.vm)
	if v.heap != nil {
		C.free(v.heap)
	}
	for _, ptr := range v.dataPtrs {
		C.free(ptr)
	}
}

// NewVM wraps function `sealevel_vm_create`.
// Internally calls `solana_rbpf::vm::EbpfVm::new`.
func NewVM(exec *Executable, heap []byte, regions []Region) (*VM, error) {
	vm := new(VM)
	runtime.SetFinalizer(vm, (*VM).free)

	vm.heap = C.CBytes(heap)

	vm.dataPtrs = make([]unsafe.Pointer, len(regions))
	cRegions := make([]C.sealevel_region, len(regions))
	for i, region := range regions {
		cRegions[i] = region.ffi()
		vm.dataPtrs[i] = cRegions[i].data_addr
	}
	var cRegionsPtr *C.sealevel_region
	if len(cRegions) > 0 {
		cRegionsPtr = &cRegions[0]
	}

	exec.used = true
	vm.vm = C.sealevel_vm_create(
		exec.program,
		(*C.uint8_t)(vm.heap),
		C.size_t(len(heap)),
		cRegionsPtr,
		C.int(len(cRegions)),
	)
	if vm.vm == nil {
		return nil, currentError()
	}
	return vm, nil
}

// Execute runs the program with the preconfigured inputs.
//
// Wraps `sealevel_vm_execute`,
// which calls `EbpfVm::execute_program_interpreted`
//          or `EbpfVm::execute_program_jit`
// depending on whether the program was compiled.
//
// Returns the content of general-purpose register 0 or any execution error.
func (v *VM) Execute() (r0 uint64, err error) {
	r0 = uint64(C.sealevel_vm_execute(v.vm))
	err = currentError()
	return
}
