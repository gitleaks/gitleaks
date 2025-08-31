package config

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestCommitAllowed(t *testing.T) {
	tests := []struct {
		allowlist     Allowlist
		commit        string
		commitAllowed bool
	}{
		{
			allowlist: Allowlist{
				Commits: []string{"commitA"},
			},
			commit:        "commitA",
			commitAllowed: true,
		},
		{
			allowlist: Allowlist{
				Commits: []string{"commitB"},
			},
			commit:        "commitA",
			commitAllowed: false,
		},
		{
			allowlist: Allowlist{
				Commits: []string{"commitB"},
			},
			commit:        "",
			commitAllowed: false,
		},
	}
	for _, tt := range tests {
		isAllowed, _ := tt.allowlist.CommitAllowed(tt.commit)
		assert.Equal(t, tt.commitAllowed, isAllowed)
	}
}

func TestRegexAllowed(t *testing.T) {
	tests := []struct {
		allowlist    Allowlist
		secret       string
		regexAllowed bool
	}{
		{
			allowlist: Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile("matchthis")},
			},
			secret:       "a secret: matchthis, done",
			regexAllowed: true,
		},
		{
			allowlist: Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile("matchthis")},
			},
			secret:       "a secret",
			regexAllowed: false,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.regexAllowed, tt.allowlist.RegexAllowed(tt.secret))
	}
}

func TestPathAllowed(t *testing.T) {
	tests := []struct {
		allowlist   Allowlist
		path        string
		pathAllowed bool
	}{
		{
			allowlist: Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile("path")},
			},
			path:        "a path",
			pathAllowed: true,
		},
		{
			allowlist: Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile("path")},
			},
			path:        "a ???",
			pathAllowed: false,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.pathAllowed, tt.allowlist.PathAllowed(tt.path))
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		input    Allowlist
		expected Allowlist
		wantErr  error
	}{
		"empty conditions": {
			input:   Allowlist{},
			wantErr: errors.New("must contain at least one check for: commits, paths, regexes, or stopwords"),
		},
		"deduplicated commits and stopwords": {
			input: Allowlist{
				Commits:   []string{"commitA", "commitB", "commitA"},
				StopWords: []string{"stopwordA", "stopwordB", "stopwordA"},
			},
			expected: Allowlist{
				Commits:   []string{"commita", "commitb"},
				StopWords: []string{"stopworda", "stopwordb"},
			},
		},
	}

	for _, tt := range tests {
		// Expected an error.
		err := tt.input.Validate()
		if err != nil {
			if tt.wantErr == nil {
				t.Fatalf("Received unexpected error: %v", err)
			} else if !assert.EqualError(t, err, tt.wantErr.Error()) {
				t.Fatalf("Received unexpected error, expected '%v', got '%v'", tt.wantErr, err)
			}
		} else {
			if tt.wantErr != nil {
				t.Fatalf("Did not receive expected error: %v", tt.wantErr)
			}
		}

		var (
			regexComparer = func(x, y *regexp.Regexp) bool {
				// Compare the string representation of the regex patterns.
				if x == nil || y == nil {
					return x == y
				}
				return x.String() == y.String()
			}
			arrayComparer = func(a, b string) bool {
				return a < b
			}
			opts = cmp.Options{
				cmp.Comparer(regexComparer),
				cmpopts.SortSlices(arrayComparer),
				cmpopts.IgnoreUnexported(Allowlist{}),
			}
		)
		if diff := cmp.Diff(tt.expected, tt.input, opts); diff != "" {
			t.Errorf("diff: (-want +got)\n%s", diff)
		}
	}
}

var benchCommitAllowlist = func() *Allowlist {
	allowlist := Allowlist{
		Commits: []string{
			"ba1beca8ac634d8b202e0daffebecceeb6dda2fc",
			"74b19abcd33ff3a6cac8aebdcfccacde9ad40f5c",
			"11ed23ff2df37b2c114ac13dbd902e3bdb8b9c63",
			"d39bcd0ebd3c9fb8d2f1bfbc98fc92bceeb3eed3",
			"faf321cf8f9f2cf654fab12f72ef64e6ffb7237e",
			"5486ce1abcdfcc862efeb6f5071a1ddef0fb3926",
			"fbcfdbdffdabf1c0f627ecdfcda91ca8c1b533ce",
			"3db86dce50f1d99fe820a4bf42ffedaefedb1bcf",
			"18ccec6cb316ce1abed9e8ec262ecd3dd4a3e222",
			"20f1cc29eaa028e7e6bcdc82f2103c1af3899c5c",
			"d90b5572e9bdb0cebf5edc3ad412c38ecd6b8ca6",
			"a0c7a0addf82d2a84babdd8be1f3cee887cb69cf",
			"0c3c967d21bca179e2d60b738fab848be9a65a45",
			"85cb3ac8817afad5ffde45a29036f4a1fa8af2eb",
			"cb9c19a9dcb05bebca7dacbed9b8afefeb2dc5ad",
			"4bac7b9fbdc851caf3c5f0cece85acaa3ebb7fd2",
			"ad2bfd0c271bbb1ac991fdfefcabb6dcc43cb3f5",
			"0c522c2750ec2fdf134721ea6000841fed5ffdd1",
			"fedbf91dddc017f9994edc7f3a75dcd9eabfdd2c",
			"9e5205bdeb080d84bfb25dfcc86dccc3fe5be499",
			"b5476d7901b105c2fdb5fc87a9f4fabdb40daf81",
			"f8fdbc509fb3c3ef1c1cbe8e70ac933ac4109cc3",
			"92727ea97463cd55eed3069ab54483ba20b94f3c",
			"e4a01ce6fdb6f6a39d2c781f7dcba3ae37973d0b",
			"dcdd273bdf8159faf60bfca6b2a20a98a9985cf3",
			"3f1efb9b7705cc1cae9ebeafa8eaf95ab79d6bea",
			"20831ce7da9e2cb78ad8cd2a73ca693d8ffaee9c",
			"edffec40aa85fbf947b20b3ffcfe6e7f6a94d017",
			"cfbbc60acefdc1f04ad26e022fba21f72ce5c25b",
			"3beac0da108cbb4fac1ebcd060ba2b67aafbefdd",
			"21a87495e1f1f4ee9d9dfab1c3e5ffbe4b6e7dba",
			"a2a3e8ba9dcae74d7bc1267f07fec3a44a0c9b08",
			"abe2c2ff0a9befc1cbae77ea6aebf8d3a46ee68f",
			"9f9e4cea3bee21deb769f830bcf76185eba76ab6",
			"48e2f92ccdd1cb33e10eba117386cb054e06f2e0",
			"4e10cc0ae797adce6cec0beda8782b28ba2dcf8c",
			"7d6eb5bc7bbee783ab012ee290f8b9acabe38367",
			"bc5d1b99fd2cbacb225e574fd05c57a3f44ca35c",
			"9a3ea6fd3dcfd135ea3b9bc63ab6494f5c54faaf",
			"fc62eec1f10e646ec9a8dacaddf1becae7e31823",
			"fd01d7f4dab422fba5b9abfeacee14aad6db0dee",
			"d7a2bcbcab6a4f4af02dde8ceeef5b6ab0fd6ca5",
			"0b1bf0ebfc1cca19eeb029cfb8e4abd8e72d82df",
			"a1ea3f771dfbae1cadbc67c803b8b07081f3fdd0",
			"78dfa84c70545f295b3b8fa3f8bd53d316ff682e",
			"ca595eebf56ad6f118be2c5ddbeadac675a588ad",
			"faadceaec7d0bb9cbef7e7f6cddc3a0fdb8e33b8",
			"0b006e37964c7b1e3cdbafd21fe8e887886cb909",
			"dffb3dfb72fa42ed49a69dae3838eaaf2a957ee0",
			"2d927ebda284a25fb2cd8fc0dd42c9b7d333db5a",
			"ffca0cdcbe9e33fd18a3bf692ea0f2a62d685aa4",
			"ac0d9a8adbe32cbe7f99fdeccf22b5bf767d06fa",
			"f4a2a0a2833f4cbcc2db2accd7cc4feacdeeeaed",
			"5f4a1e0dcbd49ed99eadf4bf837f1efafea663c1",
			"3e69fb30ea6761771f877d82ef8ee799eb1f56a0",
			"2e13cb4dec42ca80918e2bdefb5df96bf9b1eebc",
			"d480ed3e25cb82782bb6b3f0fffce8f7c3d9840b",
			"7bd34bf663bd5900f0be9accb2091e3dc4a378bc",
			"a9fdc3ccc7cfd3b2a73b55b957bbe73beedba2ea",
			"b7ca933acc3ef5c8c5bfaede6bfc4f9acc7f4f39",
			"248a04fea1bfc38f4a1b76ea4ce399ef0affe4cb",
			"8ae496b4fb06c46ae5bfcdceda5e9773ca9ce25b",
			"0ac468471f71e8d17c21eb9fe4d922549e13bc3a",
			"db082f214cdbff93cdaefebabae455f2ed994730",
			"df0c6eabe5ccffed0bf840f3c45a8fdf39c04f9b",
			"aacaadfd5bd1e9efd6fc8a9b7ad8fe93ec3bbf23",
			"4e9cbeaabc66d01da99cd85cbaf8db5bfaccf5c4",
			"28b39fd14b2c8dbeab86aea69de0b5ccdf4ff7b2",
			"a20ebfbef4c75e906a114eaad6a67deadb810ed9",
			"f8fd3b4cd75b6fc28e21289e6d4ef7c4c7f22f68",
			"ccf7e03c5f5c7d6fdbd9fbde2fd342ae15cbbe4e",
			"cdcbcfe7c6d4cee31a27f338d1ff66d3cad4bbd5",
			"d7c03aba693ba8de8aaea7fa9d8d46a733cd5989",
			"48e3f4abb26eb44eefcaf3f188cea00cce46ddc1",
			"c1a9c25e5e29804abbc8a0fccf1faf384fea28a5",
			"f9e090c6b2af0ee3bde57f4a0352f5b02e675d35",
			"1df2354e9eee4934c34dcbd2de0b1df9b5dcadac",
			"7da5ad4d8fa965ea4aa4613a9dc4eabdc3406eeb",
			"fe33bfb676572e7fafd8ae9ea88e0efa3c109bdd",
			"fefeea80b187eefce0a9c184cb76976c2fcef98a",
			"eea8efae44ab9eb43a5954df7fa63bb55fa1d8dc",
			"f559c7bbe6b6bfba56e7f362604c721c2fee6d0d",
			"bf1dbe006b93fb443aebbe77a2c9cfdfc3f6a6a0",
			"cfd00d87f7bc44ed7bdcebbf493869a495ebfef8",
			"7ca45a388fd9aaeb8ed7701c2af2beff9e52eebb",
			"ca47c2fdb73b2d39a1eab115dffa1ef7a5ffacd0",
			"cc0954dfddaabb996abc78c28dff83f7e3edb828",
			"ad4adc1195dabcfaf0f7eaac4f3f3f6b152d7fd4",
			"ab3e6b6ed2eb6dcd4ae4fd0db76efdecd72ecfaa",
			"d16ccd31d433f7a41eceb7d544081c72b4d9bf3e",
			"d0dbe09bb150bbd5bb4b85adc273df87350e7e6c",
			"492bbbcaf6edd864dd3ca0aee5d4d60b1cd4214b",
			"d73dbbe7a9effb828793a3adad04cecb1843ccbd",
			"89b12dcbfc40e30ddecd7a19e0cf1e32a29ebccb",
			"1cd815bd965ee0fd2e15bbe28c94688f15ebb3ad",
			"a7f9b3babda7abfe0316bf7aeded7df7cfcf7bdf",
			"9e832d5ebecc2e5aead9b5cdcdd6d2ba4dfeaee7",
			"43fa54761faa5f8beffe9acfd402fcd24dfede71",
			"dada4b08ae4aa37cff754b4ca29ebc134c54bac1",
			"1b708f1fad29cc62bc39ae5dda8e9124acc00d2d",
		},
	}
	_ = allowlist.Validate()
	return &allowlist
}()

func BenchmarkCommitAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok, _ := benchCommitAllowlist.CommitAllowed("d0dbe09bb150bbd5bb4b85adc273df87350e7e6c")
		assert.True(b, ok)
	}
}

func BenchmarkCommitNotAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok, _ := benchCommitAllowlist.CommitAllowed("5fe58bf0b0be1735ad27aa6053b56323a905c223")
		assert.False(b, ok)
	}
}

var benchRegexAllowlist = func() *Allowlist {
	a := Allowlist{
		RegexTarget: "match",
		Regexes: []*regexp.Regexp{
			// Based on patterns from `generic.go`
			regexp.MustCompile(`(?i)access(ibility|or)`),
			regexp.MustCompile(`(?i)access[_.-]?id`),
			regexp.MustCompile(`(?i)random[_.-]?access`),
			regexp.MustCompile(`(?i)api[_.-]?(id|name|version)`),
			regexp.MustCompile(`(?i)rapid|capital`),
			regexp.MustCompile(`(?i)[a-z0-9-]*?api[a-z0-9-]*?:jar:`),
			regexp.MustCompile(`(?i)author`),
			regexp.MustCompile(`(?i)X-MS-Exchange-Organization-Auth`),
			regexp.MustCompile(`(?i)Authentication-Results`),
			regexp.MustCompile(`(?i)(credentials?[_.-]?id|withCredentials)`),
			regexp.MustCompile(`(?i)(bucket|foreign|hot|idx|natural|primary|pub(lic)?|schema|sequence)[_.-]?key`),
			regexp.MustCompile(`(?i)key[_.-]?(alias|board|code|frame|id|length|mesh|name|pair|ring|selector|signature|size|stone|storetype|word|up|down|left|right)`),
			regexp.MustCompile(`(?i)key[_.-]?vault[_.-]?(id|name)|keyVaultToStoreSecrets`),
			regexp.MustCompile(`(?i)key(store|tab)[_.-]?(file|path)`),
			regexp.MustCompile(`(?i)issuerkeyhash`),
			regexp.MustCompile(`(?i)(?-i:[DdMm]onkey|[DM]ONKEY)|keying`),
			regexp.MustCompile(`(?i)(secret)[_.-]?(length|name|size)`),
			regexp.MustCompile(`(?i)UserSecretsId`),
			regexp.MustCompile(`(?i)(io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)`),
			regexp.MustCompile(`(?i)(api|credentials|token)[_.-]?(endpoint|ur[il])`),
			regexp.MustCompile(`(?i)public[_.-]?token`),
			regexp.MustCompile(`(?i)(key|token)[_.-]?file`),
			regexp.MustCompile(`([A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(\n|\z)`),
			regexp.MustCompile(`([A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(\n|\z)`),
		},
	}
	_ = a.Validate()
	return &a
}()

func BenchmarkRegexAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok := benchRegexAllowlist.RegexAllowed(`environment {
	CREDENTIALS_ID = "K8S_CRED"
}`)
		assert.True(b, ok)
	}
}

func BenchmarkRegexNotAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok := benchRegexAllowlist.RegexAllowed(`"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`)
		assert.False(b, ok)
	}
}

var benchPathAllowlist = func() *Allowlist {
	a := Allowlist{
		Paths: []*regexp.Regexp{
			// Copied from `base/config.go`
			regexp.MustCompile(`gitleaks\.toml`),
			regexp.MustCompile(`(?i)\.(bmp|gif|jpe?g|svg|tiff?)$`),
			regexp.MustCompile(`\.(eot|[ot]tf|woff2?)$`),
			regexp.MustCompile(`(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$`),
			regexp.MustCompile(`go\.(mod|sum|work(\.sum)?)$`),
			regexp.MustCompile(`(^|/)vendor/modules\.txt$`),
			regexp.MustCompile(`(^|/)vendor/(github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(/.*)?$`),
			regexp.MustCompile(`(^|/)gradlew(\.bat)?$`),
			regexp.MustCompile(`(^|/)gradle\.lockfile$`),
			regexp.MustCompile(`(^|/)mvnw(\.cmd)?$`),
			regexp.MustCompile(`(^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`),
			regexp.MustCompile(`(^|/)node_modules(/.*)?$`),
			regexp.MustCompile(`(^|/)(npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),
			regexp.MustCompile(`(^|/)bower_components(/.*)?$`),
			regexp.MustCompile(`(^|/)(angular|bootstrap|jquery(-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(\.min)?\.js(\.map)?$`),
			regexp.MustCompile(`(^|/)javascript\.json$`),
			regexp.MustCompile(`(^|/)(Pipfile|poetry)\.lock$`),
			regexp.MustCompile(`(?i)/?(v?env|virtualenv)/lib(64)?(/.*)?$`),
			regexp.MustCompile(`(?i)(^|/)(lib(64)?/python[23](\.\d{1,2})+|python/[23](\.\d{1,2})+/lib(64)?)(/.*)?$`),
			regexp.MustCompile(`(?i)(^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(/.+)?$`),
			regexp.MustCompile(`(^|/)vendor/(bundle|ruby)(/.*?)?$`),
			regexp.MustCompile(`\.gem$`),
			regexp.MustCompile(`verification-metadata\.xml`),
			regexp.MustCompile(`Database.refactorlog`),
		},
	}
	_ = a.Validate()
	return &a
}()

func BenchmarkPathAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok := benchPathAllowlist.PathAllowed(`src/main/resources/static/js/jquery-ui-1.10.4.min.js`)
		assert.True(b, ok)
	}
}

func BenchmarkPathNotAllowed(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ok := benchPathAllowlist.PathAllowed(`azure_scale_templates/sub_modules/vpc_template/inputs.auto.tfvars.json_backup`)
		assert.False(b, ok)
	}
}
