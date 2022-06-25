// Package sealevel interfaces with SBF runtime of the Solana Rust implementation.
package sealevel

// #cgo LDFLAGS: -lsealevel
// #include <sealevel.h>
import "C"

import (
	"runtime"
	"unsafe"
)

// Config wraps solana_rbpf::vm::Config.
type Config *C.sealevel_config

// NewConfig creates a new config object based on the given options.
//
// Calls `sealevel_config_new` and sets it up using `sealevel_config_setopt`.
func NewConfig(opts *ConfigOpts) Config {
	config := C.sealevel_config_new()
	runtime.SetFinalizer(config, func(config *C.sealevel_config) {
		C.sealevel_config_free(config)
	})
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
	return config
}

func bool2size(b bool) C.size_t {
	if b {
		return 1
	} else {
		return 0
	}
}

// SyscallRegistry wraps solana_rbpf::vm::SyscallRegistry.
type SyscallRegistry struct {
	inner C.sealevel_syscall_registry
}

// NewSyscallRegistry wraps `sealevel_syscall_registry_new`.
func NewSyscallRegistry() *SyscallRegistry {
	registry := C.sealevel_syscall_registry_new()
	wrapper := &SyscallRegistry{inner: registry}
	runtime.SetFinalizer(wrapper, (*SyscallRegistry).free)
	return wrapper
}

func (s *SyscallRegistry) free() {
	C.sealevel_syscall_registry_free(s.inner)
}

// Error maps to solana_rbpf::error::EbpfError.
type Error struct {
	Code    int
	Message string
}

// Error codes (enum branches of solana_rbpf::error::EbpfError)
const (
	ErrUnknown                 = C.SEALEVEL_ERR_UNKNOWN
	Ok                         = C.SEALEVEL_OK
	ErrInvalidElf              = C.SEALEVEL_ERR_INVALID_ELF
	ErrSyscallRegistration     = C.SEALEVEL_ERR_SYSCALL_REGISTRATION
	ErrCallDepthExceeded       = C.SEALEVEL_ERR_CALL_DEPTH_EXCEEDED
	ErrExitRootCallFrame       = C.SEALEVEL_ERR_EXIT_ROOT_CALL_FRAME
	ErrDivideByZero            = C.SEALEVEL_ERR_DIVIDE_BY_ZERO
	ErrDivideOverflow          = C.SEALEVEL_ERR_DIVIDE_OVERFLOW
	ErrExecutionOverrun        = C.SEALEVEL_ERR_EXECUTION_OVERRUN
	ErrCallOutsideTextSegment  = C.SEALEVEL_ERR_CALL_OUTSIDE_TEXT_SEGMENT
	ErrExceededMaxInstructions = C.SEALEVEL_ERR_EXCEEDED_MAX_INSTRUCTIONS
	ErrJitNotCompiled          = C.SEALEVEL_ERR_JIT_NOT_COMPILED
	ErrInvalidVirtualAddress   = C.SEALEVEL_ERR_INVALID_VIRTUAL_ADDRESS
	ErrInvalidMemoryRegion     = C.SEALEVEL_ERR_INVALID_MEMORY_REGION
	ErrAccessViolation         = C.SEALEVEL_ERR_ACCESS_VIOLATION
	ErrStackAccessViolation    = C.SEALEVEL_ERR_STACK_ACCESS_VIOLATION
	ErrInvalidInstruction      = C.SEALEVEL_ERR_INVALID_INSTRUCTION
	ErrUnsupportedInstruction  = C.SEALEVEL_ERR_UNSUPPORTED_INSTRUCTION
	ErrErrExhaustedTextSegment = C.SEALEVEL_ERR_ERR_EXHAUSTED_TEXT_SEGMENT
	ErrLibcInvocationFailed    = C.SEALEVEL_ERR_LIBC_INVOCATION_FAILED
	ErrVerifierError           = C.SEALEVEL_ERR_VERIFIER_ERROR
)

// Returns the current thread-local error.
func currentError() error {
	errno := int(C.sealevel_errno())
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
}

// LoadProgram wraps `sealevel_load_program`.
func LoadProgram(config Config, syscalls *SyscallRegistry, elf []byte) (*Executable, error) {
	var elfPtr *C.char
	if len(elf) > 0 {
		// only borrowed, no copy needed … i think?
		elfPtr = (*C.char)(unsafe.Pointer(&elf[0]))
	}

	program := C.sealevel_load_program(
		config,
		syscalls.inner,
		elfPtr,
		(C.size_t)(len(elf)),
	)
	if program == nil {
		return nil, currentError()
	}
	exec := &Executable{
		program: program,
		used:    false,
	}
	runtime.SetFinalizer(exec, func(exec *Executable) {
		if !exec.used {
			// TODO destroy program
		}
	})
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
	Data      []byte
	VMAddr    uint64
	VMGapSize uint64
	Writable  bool
}

func (r Region) ffi() C.sealevel_region {
	return C.sealevel_region{
		data_addr:   C.CBytes(r.Data), // copy :(
		data_size:   C.size_t(len(r.Data)),
		vm_addr:     C.uint64_t(r.VMAddr),
		vm_gap_size: C.uint64_t(r.VMGapSize),
		is_writable: C.bool(r.Writable),
	}
}

// VM wraps struct `sealevel_vm`.
type VM struct {
	vm       *C.sealevel_vm
	heap     unsafe.Pointer
	dataPtrs []unsafe.Pointer
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
