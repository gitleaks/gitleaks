package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func PuttyPrivateKey() *config.Rule {
	r := config.Rule{
		Description: "Identified a Putty Private Key, which may compromise cryptographic security and sensitive data encryption.",
		RuleID:      "putty-private-key",
		Path:        regexp.MustCompile(`(?i)\.ppk$`),
		Regex:       regexp.MustCompile(`Private-Lines: \d+\s+([\n\S-]+)\s+[A-Za-z0-9-:]+`),
		Keywords:    []string{"PuTTY-User-Key-File-"},
		Allowlist: config.Allowlist{
			Description: "Ignore private key protected by a passphrase",
			Regexes:     []*regexp.Regexp{regexp.MustCompile(`Encryption: [^n][^o][^n][^e]`)},
			RegexTarget: "raw",
		},
	}

	tps := []detect.Fragment{
		{
			FilePath: "dsa-key-20240314.ppk",
			Raw: `
						PuTTY-User-Key-File-3: ssh-dss
						Encryption: none
						Comment: dsa-key-20240314
						Public-Lines: 18
						AAAAB3NzaC1kc3MAAAEBAIpeviC974g40YTx0CuxCWjGwWPA97aC7GbnVeB1J4SD
						A+9r6CtOk+r6bbWTO2UOgN1Nw/wBvUXIGGByOVkkY1G49rY4XWpekrA/OQEtLjdY
						C0mCQyLRCt72+Q7MGwjnBcP4a7fA7A/Z8T/4Gljp1VpHWfauhvSzS3emr3gDVdhB
						O5D/J4ApDyaMn4GZ7P0ooyntQY1CT7cmJuMw9SKJR0rYUPrJK0BqxTUtq9rbcqwb
						9D0ugh+NH5SpmoX7SuvD/T/SHRxTbKhYWIQEYA1tGwIijkOxRSqhS8ISPPntKLW9
						CeFWqmrY5odFVByRin6q18Wi/IB9HRqo9y2MCRqOhLsAAAAVAJt1uH4ZwTN4yugv
						qS1OrO4DGVl9AAABAQCEwbRowR99EcSo8VhM6QdtP34j6GU59hX550gL3LMtmANm
						P10XhuMe6zIkZteEuA2HMJCCUEAoB+4h2uy64p9ch3Vku4a8qJr/BW/cG/+yGtQw
						HznOehEQh8lAQJIx5EP5Lx6fDDYMRpHgRPIYMNlUx9jJOd2xzmDVjUjd5IaDzEfb
						P6Jslp8xcsFKhm2W7cLW30jHpA5FkuhqB9Lso/eQw4l4sUD/CMYtyZgKjBRwGDn9
						gRAn88/G23VSVKm6KdKHiuIbtTyCokPMJcqsLLvOkiakgZ00dzIpQgrH1y4HmM78
						hqUETurduN+EGGDWgb2cicd2FpAGDCU0IlQ9V+c0AAABAANPWGlC3LJAsIei44lR
						3W7hELFGMHy5US7UvlO5hZMvLSu5+dvjU4Q+Jqv13o1ZQA0RnzsAy35uBwzyeF/y
						/ZU8SHSYl0k7bwsXHB618xjWCDW93tHwI+/oevwyZzVcHFDR9KNceaWkXlOraagO
						CXfU05DaE5kt9nEvovBNQQb96nJvGiBcV1/jxZ8MQrX/zZUgdrQ6AAoWVgeQ3Kfj
						J+PjZh6SuKVIb8+D/RYNrOFOUQu+uzcI4/VorEoPQObjL7VzOtPy2sxyF+TPeLOI
						pEw/TeYsOeDv6egtMQKNWGeL9y8/z/IJu4tONCoXrQJ4Q8v0JHQ2q3XREE2RfzWP
						Uyw=
						Private-Lines: 1
						AAAAFFADQ+s+X6fltaX5ADIslRHnLYcd
						Private-MAC: e01458212c8d218b16ccd35800a225c17acc12d58ec7fc54c20a106141451305
					`,
		},
		{
			FilePath: "path/to/rsa-key-20240314.ppk",
			Raw: `
		PuTTY-User-Key-File-3: ssh-rsa
		Encryption: none
		Comment: rsa-key-20240314
		Public-Lines: 6
		AAAAB3NzaC1yc2EAAAADAQABAAABAQCVXOpGY7pY//q0d9Bm3XcauPrj75po0trZ
		lC1Gh4tDIMyl19xQqSG2rLE2sfgGjgK/8QuZMk2ZdbbshDGOSG8WmBb/wuseeJYH
		UGcNDddbssyTMcN/jnL2E4KLu1C6LW6ToBUogK5rvgFs0bBm2QCmGo2nOvc0IiWj
		LZD0+6MoL9KUgcCBqvYmwwdaU0Gpr7GlHKrQ7P6j6cLXUqcfXcSE+2QBk8yfvKIW
		miZyjHxyz0u6yzsIhBc/raaRLNbilXLa0Efkv4n9h9mpdvXfo4ofnQfn/MkSHJF6
		oKWYR1Nn2MGi+M8TIwnL+O4/9l6Rzg43G4pZpioh0J6u47wpd8xx
		Private-Lines: 14
		AAABACJPG4lbsxxqgF4f/4EBcjBzOT5OdXuKo7bC8Lt4uyaKTDf0I6lrkFDzzikw
		LDblPAB3ECD6ixSrE3+0xeVXAh2Ahhft4DA5psy7TVCUU1m+8nsFPVD5mbKovJ34
		QwzhDrteVD3fgTFCjfU/HXQieKGvC8bUJqCVD2wyNU/w1YOPTgyazXF6oqV7vRTM
		GAoXkrM9OwA7gD21e+ZXpoou3nne7zX9QUIZNV68LcDrxS6exC27IqMougruTH+t
		ADwZuKjxbe6arj21+eEFoZNDNuO+YWXTiTisaKpt8blMoVBLnmXkDb8aP4sntMd+
		uJnzgLO/YbnenApC86vsN2NmkiEAAACBAN52GNPMnEbj2LBqbNiVbi65Wpf4OOeQ
		4QRn97YcfNaKTli0x3AMo1RCGBAM/sRWdRr42IaoIRftsJsLD29TnYs7PEagmbht
		MWtbJ94XriL0KjQSHkvclARYBTmaH/GIbJe2NEarKcHBYMRe9OGDfymbCQqaXazR
		NNApH0HgCO2tAAAAgQCr4ZV6ZFBs8CkLzEVJYLgPVo2xWK2NT0Wp/1S8iQcUIHja
		YGompPJWKerMeOn0eTPy2W1gKRiG7XJKTvUr0Q1jAOpyHSB26wp91PdnFEy01ZVc
		9r3ji1ljsha1b2dyy1/OV4UtPL75yt7oSRZwBK5rIq+aslG99GwXMF43+NyqVQAA
		AIEAwsuoZkAqq09RG/DP0nEzsPaf16heb3WxvnrczM7pDqAxgD+1VM3L9WZUCdiO
		DjUM2ZgaRS/cwWKfhTsTdBNhlC3tku+6fHNlitmmnsrj0T8HT3fbLLQ7b7D2I9t2
		MTQElrixH/aJ20UcePIVR22I/RmEaS1uJL2SmKvm4uLutIE=
		Private-MAC: 04dc4dfdfb21a070395413c6ba9e246ccdd830d2561983f9eeab5e72f299d8f7
				`,
		},
	}
	fps := []detect.Fragment{
		{
			FilePath: "ecdsa-key.ppk",
			Raw: `
				PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
				Encryption: aes256-cbc
				Comment: Private key protected by a passphrase
				Public-Lines: 3
				AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPXuPjvVPvVY
				Sgn+fcEP/kdmaBM1Vf4zV4Kjup/fftK4YtPgIYiCI3tS0hlCY7FwkqFsUCxWs0ct
				vXLcxNpYALQ=
				Key-Derivation: Argon2id
				Argon2-Memory: 8192
				Argon2-Passes: 3
				Argon2-Parallelism: 1
				Argon2-Salt: a647a1cd3cba6b26830fee829c37473d
				Private-Lines: 1
				FF6XTS+aW43YfvrKDTsWK6Ld8NDGQKUnyLNJiezr7HNi/Y6ZfNNEUl9W8zR5H+t7
				Private-MAC: eb7b22e0e79122bf0abf5ca4f43bd89ad004475aca39853ae41d991c1fb3d35d
			`,
		},
		{
			FilePath: "id_rsa",
			Raw: `
				PuTTY-User-Key-File-3: ssh-dss
				Encryption: none
				Comment: Fragment with wrong FilePath
				Public-Lines: 2
				AAAAB3NzaC1kc3MAAAEBAIpeviC974g40YTx0CuxCWjGwWPA97aC7GbnVeB1J4SD
				Uyw=
				Private-Lines: 1
				AAAAFFADQ+s+X6fltaX5ADIslRHnLYcd
				Private-MAC: e01458212c8d218b16ccd35800a225c17acc12d58ec7fc54c20a106141451305
			`,
		},
		{
			Raw: `
				PuTTY-User-Key-File-3: ssh-dss
				Encryption: none
				Comment: Fragment without FilePath
				Public-Lines: 2
				AAAAB3NzaC1kc3MAAAEBAIpeviC974g40YTx0CuxCWjGwWPA97aC7GbnVeB1J4SD
				Uyw=
				Private-Lines: 1
				AAAAFFADQ+s+X6fltaX5ADIslRHnLYcd
				Private-MAC: e01458212c8d218b16ccd35800a225c17acc12d58ec7fc54c20a106141451305
			`,
		},
	}

	return validateFragments(r, tps, fps)
}
