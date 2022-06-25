package sealevel

// NewConfigOpts should be used to create a new ConfigOpts object.
func NewConfigOpts() *ConfigOpts {
	return &ConfigOpts{
		NoVerify:                       false,
		MaxCallDepth:                   20,
		StackFrameSize:                 4096,
		EnableStackFrameGaps:           true,
		InsnMeterCheckpointDist:        10000,
		EnableInsnMeter:                true,
		EnableInsnTracing:              false,
		EnableSymbolAndSectionLabels:   false,
		DisableUnresolvedSymsAtRuntime: true,
		RejectBrokenELFs:               false,
		NoopInsnRate:                   256,
		SanitizeUserProvidedValues:     true,
		EncryptEnvRegisters:            true,
		DisableDeprecatedLoadInsns:     true,
		SyscallBPFFuncHashColission:    true,
		RejectCallxR10:                 true,
		DynamicStackFrames:             true,
		EnableSdiv:                     true,
		OptimizeRodata:                 true,
		StaticSyscalls:                 true,
		EnableELFVaddr:                 true,
	}
}

type ConfigOpts struct {
	NoVerify bool

	MaxCallDepth                   uint
	StackFrameSize                 uint
	EnableStackFrameGaps           bool
	InsnMeterCheckpointDist        uint
	EnableInsnMeter                bool
	EnableInsnTracing              bool
	EnableSymbolAndSectionLabels   bool
	DisableUnresolvedSymsAtRuntime bool
	RejectBrokenELFs               bool
	NoopInsnRate                   uint32
	SanitizeUserProvidedValues     bool
	EncryptEnvRegisters            bool
	DisableDeprecatedLoadInsns     bool
	SyscallBPFFuncHashColission    bool
	RejectCallxR10                 bool
	DynamicStackFrames             bool
	EnableSdiv                     bool
	OptimizeRodata                 bool
	StaticSyscalls                 bool
	EnableELFVaddr                 bool
}
