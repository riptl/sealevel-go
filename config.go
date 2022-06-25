package sealevel

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
