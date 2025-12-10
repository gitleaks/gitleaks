package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func PrivateKey() *config.Rule {
	// language=regexp
	headerPat := `-----BEGIN[ \w-]{0,100}PRIVATE KEY(?: BLOCK)?-----`
	// language=regexp
	footerPat := `-----[ \t]{0,5}END[ \w-]{0,100}KEY(?: BLOCK)?[ \t]{0,5}-----`
	// define rule
	r := config.Rule{
		RuleID:      "private-key",
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex: regexp.MustCompile(fmt.Sprintf(
			// language=regexp
			`(?i)%s(?:(?:\\r|\r|\\n|\n){0,5}.*?){0,5}?(?:(?:\\r|\\n|[ \t\r\n]){1,5}.*?[a-z0-9/+]{64,}.*?)*?(?:(?:\\r|\\n|[ \t\r\n]){1,5}.*?[a-z0-9/+]{4,}={0,3}.*?)(?:(?:\\r|\r|\\n|\n){0,5}.*?){0,5}?%s`, headerPat, footerPat)),
		Entropy:  3.5,
		Keywords: []string{"-----BEGIN"},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					// language=regexp
					regexp.MustCompile(fmt.Sprintf(`(?i)%s.{0,50}%s`, headerPat, footerPat)),
					// language=regexp
					regexp.MustCompile(fmt.Sprintf(`(?i)%s(?:.|\s){0,50}?-----BEGIN`, headerPat)),
				},
			},
		},
	}

	// validate
	tps := []string{
		// Oneline
		`private_key	"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWY8OqlVFaE8hQ\n+pZjuv2t1mMQG0Fu15Lfa8R2r4JujafY6A9fHbwhDFibDoa7aofwKyZracs/qVUR\nwfEm7FXLFf7ptzlH3rNU+0ElAeDXM8++ePJVc4HAq+qEqW0q3yIZPlaMKpPe6Fks\nhtX7WGXxnqaiYYgGRQ4VMp0+d+KrXXe9pkCE53vqpxnry/6DsQM6fK+jjphpeCZ8\ng0mYk9u6J3RBCudlTTRSuHSyCFbsSL8v94wRv20oaEl2TT7GEWWPuQW6oIDrsCtv\n7tpt03u4GhJxyiqwFRFWHAPFCnKNk0+NoCXHzn476IplmvpRv+vl/5DY/mE+NF5k\nJLwHrSPNAgMBAAECggEAStHVfd+Nuq/O4CLbgUB9huf7Hv9AXYHYq1j1RErrLE9D\na1GAnESx3QtEZdgjRcipWt5M3fGjUcfP7+a6MDAyOrh1uxcR42SzeZsK/PtjPg2j\n1FJd1g+CRTYClf+otUSPtVljO5bPPH4CJ3npqYOALGZO5sh5IQ1oBTnKK1L/rVsu\nZO4IUiF2xTzwVyLtct+tu5Pqy5yNc3uVkiPUA+QUWH9htgEXzAH6TWgchsSVn+ao\np5WbsQksq2Ok0lpioATGInsHtMSORFCmmFhoE2SoTQKBgQDQqtN5HK535oWfaaGL\nPS6h4HWLk+mLqTVkaDx5gaYyCB1LxmIkjzllozAobVyIOE3AQ3M8yLF3Tw4hC54r\nIZ9840OM8fGs4KNOWi+P0rGONPJ9XwE31WD2zTagEutzemUsGChR8Fn8Le+iM5p4\nQ7fCWxIaQNs6oNxK6KwCHr++awKBgQC4gMv4PBM6F5bWzYvoNdDeFluq9F2dqLi2\nLaxbFn7sM5OpKcIhinn8LrNpTeNSnP0mBzOFuN+E9fqAED45jInmthz/nyVjHxtO\njmJ9KtZ+P7WnOvi8bl5hJNvr955ho0ONbX8mnZMRj5dXh8lV1usuVIPXuDl8/ZjQ\nGawul+rEpwKBgEAO4SLCClFmpEi+7cfH/YPWW1+BBeZJCMoNMdt/UJz1XsD/Yuuk\neKzrbMSRalSmE18I/3/AEG/ZTkJ2Iwqeh1AUEyeaF3MVJOueKAfylpyHAoGANPJJ\nFlBvGBGi6LuNtbKT4Ne7sKB1qQO9FhKfTnhzLedTLY1dN3DctsDUHZkLbi68+sfA\nQlSeWDKak1uV77/j5wBF7BlIilxn4rA7lT3Q1eQEhhwHO1PU473HGr0xh0Vp4lEU\n1wkLJlP1k1nVLjwBu4bnWuV0IelIjBeB8NEJvysCgYEArqkK9yomaK2w8ynjGkZy\nlVwaxMy4xdTheZJWMzMAF4c///e+Tfu63n0/yYKot3NyQye4WrYRd2GVlwnzOqzg\nlenHJyFYcBfuMUPnuDNpD5c=\n-----END PRIVATE KEY-----\n"`,
		// Quotes escaped slashes.
		// RSA Private key.
		`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArbf5BDzpW/aicN8j9WTIQwEmGC1g7CNYufbhaqpwfK9NFodC
oe+RIOR4MKy+udmXFHrW5So+0HxFn6x7Ww6P5HNSNG2I3UyC8+Ab1Ckuy8u2WG/h
ouvlKXs02c5JTCEcUiezFPu1tS36/08hmoAEbUgpdwG5rg5EClU4qgEjafssfkli
ljd+L9sXjNF7lQM3UscUyAdhStz+PykdoPOQLc7j7cWyIix3fzQo
-----END RSA PRIVATE KEY-----`,
		// Newlines after start.
		`-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOXBFmwWAsBCADZWzSQ4xqYb5s1P0eUXVCg2f03cBJdFU6KD0t9mgT//0md9zS7
3YdkE0hDfW0QAsh7+jLe+9nKetLL5XW24tga0dUf4Wg4tbjVXpDkAa8jh4OIRb02
Vd7O8KDO5P2H9mcDv14IxhdsqEY/64kU8jSZGh0bIZHxoOWtb+vRmplYGbBYoo0V
6eX6RwjFhhxNUbsOuLAeOcKT9Kiy4W6Wmqh3tRUFMPfVhD+s4E1iauqMRqxY7+XM
oskhG+DP6+lgxQ9o7g15kTUUk/hPXHQio4l0tneRIE6j1g==
=wHO1
-----END PGP PRIVATE KEY BLOCK-----`,
		// No newlines.
		`exports.ur_private_key = [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
'lQO+BFRnrwgBCACukxtBb7sUqi9TV2CoOwaJs7z9MVacUS3540/reM8tcawFl2pX',
'3mCi/LXeqfbm4UVM5ij4VUzoG9iDAwTk31tGuEW2I+tdB+dRVGUosqgOz2PsnUR5',
'2gHrXaXxDu26+zHVBtIJWj89i4KmjTE3zBdCH4p9WEf2XF2hAJU+DSJcEMyuV84P',
'0ILkicIKW5jatbRrQWRnTPMnnRWoHNsuhm4/d/cys4nwZsXnS1rswQJd7uTIyhba',
'Yq+N4wfZEW3h5+SfTrFmv5ULnyEWw5H6ZFdmMR/7tKutydH/mdWQJd8wsXHzBVSO',
'QQJOHvuKwzlyUnzVid5Wm/uAiZ8/X2o9q0Ur+q8x',
'=uoH3',
'-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');`,
		// Metadata at start.
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2.0.22 (GNU/Linux)
Comment: http://openpgpjs.org
Comment: Alice's OpenPGP Transferable Secret Key

lQH+BFa53fQBBADGhdyNIYjggwcd3w60oWaEljhxxvS41BA22ldp30eHkyfKBTvz
A8KCQPxLuXcWMP0x3BcWLEg1g2gJiXC+9s/JidZKDuHzdS9vDhaEl+rP5LBN98sR
8M+FpLJF1og/59JEma3iHFYnmzJ8uQkPTmdgQLjQ40+0cOguTnNyVDQ6lwARAQAB
/gMDAr7CmMXvGxBSYLmghsus+z/bjW0uvVbJNUsE6RwyIDqjNmQl3LELZPM7eu2d
VFtF0YIQmYdtE8DJ1mcXsazalePDmVwJ+V0lSEEXUR6mP/nvLFg8JbMbagezf0Hz
oyGyfITggFOOCV/DYB23pHNdV6DC1GbHOGaD+R9QbMsn6TelV1Wq9UxR/kykn6CU
JOBAGaR9MOU=
=Z3zA
-----END PGP PRIVATE KEY BLOCK-----
`,
		// Commented
		` // Key: \x60-----BEGIN RSA PRIVATE KEY-----
		// MIIEpAIBAAKCAQEA4e2D/qPN08pzTac+a8ZmlP1ziJOXk45CynMPtva0rtK/RB26
		// 7XC9wlRna4b3Ln8ew3q1ZcBjXwD4ppbTlmwAfQIaZTGJUgQbdsO9YA==
		// -----END RSA PRIVATE KEY-----
		// \x60`,
		`$ cat cosign.key.enc 
-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjozMjc2OCwiciI6
OCwicCI6MX0sInNhbHQiOiJaN2NxN1R6OXJxd3pGZ0xOS3BXNjVYR25ZTXVPUWI3
VjlkZ3htc3RVNHVvPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJBNGxmUDAyNXE2aW16T3hicTQ4Tk1vZlVRdjg2UFJDViJ9LCJj
aXBoZXJ0ZXh0IjoiWGxLUjdRZVJVUjM2endURWl3YzdDVytpZFdzYkF2U3dJZDRa
N2hiS3FocnQ1Z21xYWZwemU0MWlla2JrQ1RIbDdhbjBjZGhnays4SXloYVBTSVlK
MmFCWFZNYlgxVlZzY2NGL2p3eklVaHpKTnltdXNLRERGU1Fzd1Z4eStSd3UwejA0
R0FkcXpNNHNoenFQSzBhL1JSWWdsR01lcGtYbE9xZzNCUGVuQllqYk1SVDRrYm1h
cklFak94WDYxVjc1UldEdnBTTW5abG1WS3c9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD9rZeTfH
ijhs+GmsOHxZFRAAAAAQAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDRKiYi/W9W
QHbkLLwpAteIPK78mlrW1vSC7aX2iqWPBfxcgJC9JCzXai7T7etRxNX7EDYUIgCRJrixd9
jVjqA2mtqTnqk6LmUP9r1pB+X8c94uEK6KT58XvDul4uC/JQIGun81lRsBVeB066tt+oUu
baTo78aryPhYoT/4IQZOwYBeRyGr6crE7Pl/1y4oLo8EAllIX1U0v049EHMLENbEA4cAxa
vXWx+z5TArbSGzH+VCDHZVtp2TJHExKz3NsC0sY7KWpExZ3DuwgUCoeokDlPwX6yj/p6b/
IYUfPM8CWdj4mIv81+QC8W95y7iO0pVXKops0segA3Yl5m+q2+P1FZ8GpY8tUzdiBm96aE
7khP8Qt+hJMNRWfmg3sQF3PaL44VdUoGAPs1yuhkzsB3Dx0dxgdk72DUFkSiCehqXrZuhW
U9aPrvYMrtIOFhKVMWUDzEGHcRoRXQE8xf8/iHGFfFpovhy48pS0NbS467/tJLooLgs3OX
N/Qp50kAfm4pCZiLSdzPlclf5v3jUEtYBA++5X1eYaKCuMVkRU8GfD/pxWJr7nxL430d+h
oUlwSqgDnBwtzXuxQDc0JyIJWhendbCPPvdV9r1/LNVONm7CfQLIjijdlFKyhN1jh/aCUK
wVxenTxiOJfBIlNeCSkiW6frv2E9d2IpfffvdLVDSfnqPxNUbfBzloWGWPq4S3nV/umq+I
fuPwCKVSytX9QZK/jXCrNR4URzwN/kfHXVIGj2hTocXe85Im3aVKx2lDz6XamicbhwekUJ
yq/T4wQ+i8YGlD+HQR9yBTRhm5XvjxWJ8paZZ2UTrFXNeaaUY7cuRnjmnzwRoPrryDZ2/6
LKUc8yns2159BqnTm1bXnMN5V/qEUWklgm2GG3tR3vNls1tuOwJqj/HEuDGgZaGFMiMes/
MpOFI6rE6lMZX9Ol8H6MMYCWgdyIahQVsuPOod6qgT4lWQ3wtybJkwVX1KnZfi6sfquFF1
KNbGqyza4/ivQMiGYN3N4r2J6Q0h1q8blyB7dz/C+Zll0vjS204wwznH1M3lc8ueBzaTfZ
b1Da9w==
-----END OPENSSH PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4A63061E942EBE8C440E8FFF458450D0

AWvLtNYCJSqjVCHKBiTtNBFQ9xx6JnmnrhCNiYvXSayauLibZKZmV9IOp5pjJjCk
/MwOEK8x7742cDaYXysvCA3z0L/Q95zXF/u4PxSLje+bNvgnP82380dZJ0T8uMAZ
CmwTcxd6ybous4oRwKJEl0i36Tz0fdv8wDVgfuxgpgSicRRCB6Pt78Lvp8d15xyq
+2ODBhH2ynGAW/SmZvpX7pRMVlhvHHQuTHNTA7rfU92QjgJXfb/RxthfaYiPOsT5
RyrC/9sZbkPHHp5CP1+6iDwg2YJsKBN1C4uggu1WHA9fjk8cKyVKf6AYXtimTMUR
zFr2yFWvb1Wx7r3LFwozQL0Qw9n2zY/CnPwb6tbaTrPT9KfWkjJaD0Wh9OSN7b1T
HH6/Ptw+HHONQmKbjlrCN5gB/vpPPiA6Km7c568qWl2V+rgHPt01McPYDb1Yf3x7
-----END RSA PRIVATE KEY-----`,
		`string pkeyB(
    "\
-----BEGIN EC PARAMETERS----- \n\
BggqgRzPVQGCLQ== \n\
-----END EC PARAMETERS----- \n\
-----BEGIN EC PRIVATE KEY----- \n\
MHcCAQEEINQhCKslrI3tKt6cK4Kxkor/LBvM7PSv699Xea7kTXTToAoGCCqBHM9V \n\
AYItoUQDQgAEH7rLLiFASe3SWSsGbxFUtfPY//pXqLvgM6ROyiYhLkPxEulwrTe8 \n\
kv5R8/NA7kSSvcsGIQ9EPWhr6HnCULpklw== \n\
-----END EC PRIVATE KEY----- \n\
");`,
		`		pem := "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEICg7E4NN53YkaWuawpoqjfAofjzKI7Jq1f532dX+1O6QoAcGBSuBBAAK\noUQDQgAEjZcNa6Kdz6GQwXcUD9iJ+t1tJZCx7hpqBuJV2/IrQBfue8jh8H7Q/4vX\nfAArmNMaGotTpjdnymWlMfszzXJhlw==\n-----END EC PRIVATE KEY-----\n"`,
		`      RESTORE_KEY_PEM="-----BEGIN EC PRIVATE KEY-----\r\nMHcCAQEEINL5koIn4o+an+EwyDQEd4Ggnxra5j7Oro13M5klKmhaoAoGCCqGSM49\r\nAwEHoUQDQgAEPF7u1CLMe9FIBQo0MVmv7vlvqGOdSERG5nRLkNKTDUgBRxkXGqY+\r\nGbnnzXUb7j4g7VN7CuEy0SpCdFItD+63hQ==\r\n-----END EC PRIVATE KEY-----\r\n"`,
		`  "ssh_dsa_private_key": "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQCc4BcArUmK4xBb5bPLt5gdUo1Cm/P7qVYj2KDHfCfJIxUUq7u3\nCQwNDL12P9I91MctKQ/RDl8b6P7qX+uzKYxQZh9JpM3k6rGU2KM1jYXDKGbS+ZwW\njjlAB74u2VW5Ke+XMHslRCOrLHkJxQGQ7JRZ5i4JiACbI4bXhHYpEeU1xwIVAP4e\nBBXTQwlQ+XbgJ0cLx3kgQUfdAoGAZhfA5JbRNyPR0+QFzfaWUgLZFCx4JfNMvnKp\n-----END DSA PRIVATE KEY-----",
  
  "ssh_ec_private_key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJge+lj/7uQ1/e1kHU6e2Hg3yvRuJZvDT5FBmxPV76gloAoGCCqGSM49\nAwEHoUQDQgAEbB/t1yLzRoGqxRfY+p8w2sN6P9Ny7zc4Yyb8NxwF8E56RYJqRt9J\nXVpx6Bq+e72BkWIUMYIjQ4vxQwTfkjGXiQ==\n-----END EC PRIVATE KEY-----",
  `,
		`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3
yxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
	} // gitleaks:allow
	fps := []string{
		//		`-----BEGIN PRIVATE KEY-----
		//anything
		//-----END PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
  ##		...
  ##		----- END RSA PRIVATE KEY-----
`,
		`const privateKeyArmored = \x60-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----\x60; // encrypted private key`,
		`-----BEGIN PRIVATE KEY-----\n?????????==\n-----END PRIVATE KEY-----`,
		"5. Copy the whole contents from the file, with the complete ```-----BEGIN CERTIFICATE-----``` and ```-----END CERTIFICATE-----``` lines, and paste the contents in the text area of **Certificate body**, and close the text editor.",
		` -----BEGIN EC PRIVATE KEY-----
 -----END EC PRIVATE KEY-----`,
		`PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nHkVN9…\n-----END DSA PRIVATE KEY-----\n"`,
		`// pem format key path -> /xxx/xxx/id_rsa
		// the content of the keyfile shall begin with
		//      -----BEGIN RSA PRIVATE KEY----- / -----BEGIN OPENSSH PRIVATE KEY-----
		// and end with
		//       -----END RSA PRIVATE KEY----- / -----END OPENSSH PRIVATE KEY-----
		// simply generated by \x60ssh-keygen -t rsa -m PEM -b 4096\x60
		use ssh;`,
	}
	return utils.Validate(r, tps, fps)
}

func PrivateKeyPKCS12File() *config.Rule {
	// https://en.wikipedia.org/wiki/PKCS_12
	r := config.Rule{
		RuleID:      "pkcs12-file",
		Description: "Found a PKCS #12 file, which commonly contain bundled private keys.",
		Path:        regexp.MustCompile(`(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$`),
	}

	// validate
	tps := map[string]string{
		"security/es_certificates/opensearch/es_kibana_client.p12": "",
		"cagw_key.P12": "",
		"ToDo/ToDo.UWP/ToDo.UWP_TemporaryKey.pfx": "",
	}
	fps := map[string]string{
		"doc/typenum/type.P126.html":         "",
		"scripts/keeneland/syntest.p1200.sh": "",
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
