module github.com/zricethezav/gitleaks/v8

go 1.16

// replace github.com/gitleaks/go-gitdiff => ./../gitleaks-org/go-gitdiff

require (
	github.com/gitleaks/go-gitdiff v0.7.2
	github.com/google/pprof v0.0.0-20211108044417-e9b028704de0 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pkg/profile v1.6.0 // indirect
	github.com/rs/zerolog v1.25.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211110154304-99a53858aa08 // indirect
	golang.org/x/tools v0.1.5
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)
