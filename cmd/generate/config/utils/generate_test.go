package utils

import (
	"testing"
)

func TestGenerateSemiGenericRegex(t *testing.T) {
	tests := []struct {
		name              string
		identifiers       []string
		secretRegex       string
		isCaseInsensitive []bool
		validStrings      []string
		invalidStrings    []string
	}{
		{
			name:              "secret is case sensitive, if isCaseInsensitive is false",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{false},
			validStrings:      []string{"api_key=xxx"},
			invalidStrings:    []string{"api_key=XXX", "api_key=xXx"},
		},
		{
			name:              "secret is case insensitive, if isCaseInsensitive is true",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true},
			validStrings:      []string{"api_key=xxx", "api_key=XXX", "api_key=xXx"},
			invalidStrings:    []string{"api_key=x!x"},
		},
		{
			name:              "identifier is case insensitive, regardless of isCaseInsensitive",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"api_key=xxx", "ApI_KeY=xxx", "aPi_kEy=xxx", "API_KEY=xxx"},
			invalidStrings:    []string{"api!key=xxx"},
		},
		{
			name:              "identifier can be case sensitive",
			identifiers:       []string{"(?-i:[Aa]pi_?[Kk]ey|API_?KEY)"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"apikey=xxx", "ApiKey=xxx", "Apikey=xxx", "APIKEY=xxx", "api_key=xxx"},
			invalidStrings:    []string{"ApIKeY=xxx", "aPikEy=xxx"},
		},
		{
			name:              "identifier can be part of a longer word",
			identifiers:       []string{"key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"mykey=xxx", "keys=xxx", "key1=xxx", "keystore=xxx", "monkey=xxx"},
			invalidStrings:    []string{},
		},
		{
			name:              "identifier may be followed by specific characters",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key-----=xxx",
				"api_key.....=xxx",
				"api_key_____=xxx",
				"'''api_key'''=xxx",
				`"""api_key"""=xxx`,
				"api_key          =xxx",
				"api_key\t\t\t\t\t=xxx",
				"api_key\n\n\n=xxx", // potentially invalid?,
				"api_key\r\n=xxx",
				// "api_key|||=xxx",
			},
			invalidStrings: []string{
				"api_key&=xxx",
				"$api_key$=xxx",
				"%api_key%=xxx",
				"api_key[0]=xxx",
				"api_key/*REMOVE*/=xxx",
			},
		},
		{
			name:              "identifier and secret must be separated by specific operators",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key=xxx",
				"api_key: xxx",
				"<api_key>xxx",
				"api_key:=xxx",
				"api_key:::=xxx",
				// "api_key||:=xxx", // this isn't anything
				// "api_key <= xxx",
				"api_key => xxx",
				"api_key ?= xxx",
				"api_key, xxx",
			},
			invalidStrings: []string{
				"api_keyxxx",
				"api_key\txxx", // potentially valid in a tab-separated file
				"api_key; xxx",
				"api_key<xxx>",
				"api_key&xxx",
				"api_key = true ? 'xxx' : 'yyy'",
			},
		},
		{
			name:              "secret is limited by specific boundaries",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key=    xxx ",
				"api_key=xxx\n",
				"api_key=xxx\r\n",
				"api_key=\n\n\n\n\nxxx", // potentially invalid (e.g. .env.example)
				"api_key=\r\n\r\nxxx",
				"api_key=\t\t\t\txxx\t",
				"api_key======xxx;",
				"api_key='''xxx'''",
				`api_key="""xxx"""`,
				"api_key=```xxx```",
				`api_key="xxx'`, // could try to match only same opening and closing quotes, might not be worth the complexity
				`api_key="don't do it!"`,
				`api_key="xxx;notpartofthematch"`,
			},
			invalidStrings: []string{
				"api_key=_xxx",
				"api_key=xxx_",
				"api_key=$xxx",
				"api_key=%xxx%",
				"api_key=[xxx]",
				"api_key=(xxx)",
				"api_key=<xxx>",
				"api_key={xxx}",
				"<api_key>xxx</api_key>",            // potentially valid
				"example.com?api_key=xxx&other=yyy", // potentially valid
			},
		},
		// Note: these test cases do not necessarily prescribe the expected behavior of the function,
		// but rather document the current behavior, to ensure that future changes are intentional.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, isCaseInsensitive := range tt.isCaseInsensitive {
				regex := GenerateSemiGenericRegex(tt.identifiers, tt.secretRegex, isCaseInsensitive)
				for _, validString := range tt.validStrings {
					if !regex.MatchString(validString) {
						t.Errorf("Expected match, but got none, \nfor GenerateSemiGenericRegex(%v, /%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
							tt.identifiers, tt.secretRegex, isCaseInsensitive, validString, regex)
					}
				}
				for _, invalidString := range tt.invalidStrings {
					if regex.MatchString(invalidString) {
						t.Errorf("Expected no match, but got one, \nfor GenerateSemiGenericRegex(%v, /%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
							tt.identifiers, tt.secretRegex, isCaseInsensitive, invalidString, regex)
					}
				}
			}
		})
	}
}

func TestGenerateUniqueTokenRegex(t *testing.T) {
	tests := []struct {
		name              string
		secretRegex       string
		isCaseInsensitive bool
		validStrings      []string
		invalidStrings    []string
	}{
		{
			name:              "case sensitive secret",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: false,
			validStrings:      []string{"abc"},
			invalidStrings:    []string{"ABC", "Abc"},
		},
		{
			name:              "case insensitive secret",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: true,
			validStrings:      []string{"abc", "ABC", "Abc"},
			invalidStrings:    []string{"123"},
		},
		{
			name:              "allowed boundaries",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: false,
			validStrings: []string{
				"abc",
				" abc ",
				"\nabc\n",
				"\r\nabc\r\n",
				"\tabc\t",
				"'abc'",
				`"abc"`,
				"```abc```",
				"my abc's",
				".com?abc",
			},
			invalidStrings: []string{
				"abcabc",
				"_abc_",
				".com?abc&def", // potentially valid
				"/*abc*/",
				"<abc>",
				"<str>abc</str>", // potentially valid
				"{{{abc}}}",
				"abc, d",
			},
		},
		// Note: these test cases do not necessarily prescribe the expected behavior of the function,
		// but rather document the current behavior, to ensure that future changes are intentional.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex := GenerateUniqueTokenRegex(tt.secretRegex, tt.isCaseInsensitive)
			for _, validString := range tt.validStrings {
				if !regex.MatchString(validString) {
					t.Errorf("Expected match, but got none, \nfor GenerateUniqueTokenRegex(/%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
						tt.secretRegex, tt.isCaseInsensitive, validString, regex)
				}
			}
			for _, invalidString := range tt.invalidStrings {
				if regex.MatchString(invalidString) {
					t.Errorf("Expected no match, but got one, \nfor GenerateUniqueTokenRegex(/%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
						tt.secretRegex, tt.isCaseInsensitive, invalidString, regex)
				}
			}
		})
	}
}
