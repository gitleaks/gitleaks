package rules

import (
	b64 "encoding/base64"
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func JWT() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
		RuleID:      "jwt",
		Regex:       utils.GenerateUniqueTokenRegex(`ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?`, false),
		Entropy:     3,
		Keywords:    []string{"ey"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("jwt", secrets.NewSecret(`ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?`))
	tps = append(tps,
		`eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0==`,                                                                                                                                                                                                                                                                                    // gitleaks:allow
		`JWT := eyJhbGciOieeeiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic3ViZSI6IjEyMzQ1Njc4OTAiLCJuYW1lZWEiOiJKb2huIERvZSIsInN1ZmV3YWZiIjoiMTIzNDU2Nzg5MCIsIm5hbWVmZWF3ZnciOiJKb2huIERvZSIsIm5hbWVhZmV3ZmEiOiJKb2huIERvZSIsInN1ZndhZndlYWIiOiIxMjM0NTY3ODkwIiwibmFtZWZ3YWYiOiJKb2huIERvZSIsInN1YmZ3YWYiOiIxMjM0NTY3ODkwIiwibmFtZndhZSI6IkpvaG4gRG9lIiwiaWZ3YWZhYXQiOjE1MTYyMzkwMjJ9.a_5icKBDo-8EjUlrfvz2k2k-FYaindQ0DEYNrlsnRG0`,                                                                                                                                                                                                                                                                               // gitleaks:allow
		`"access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NLZXkiOiJRMzFDVlMxUFNDSjRPVEsyWVZFTSIsImF0X2hhc2giOiI4amItZFE2OXRtZEVueUZaMUttNWhnIiwiYXVkIjoiZXhhbXBsZS1hcHAiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6IjE1OTQ2MDAxODIiLCJpYXQiOjE1OTQ1ODkzODQsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTU1Ni9kZXgiLCJuYW1lIjoiYWRtaW4iLCJzdWIiOiJDaVF3T0dFNE5qZzBZaTFrWWpnNExUUmlOek10T1RCaE9TMHpZMlF4TmpZeFpqVTBOallTQld4dlkyRnMifQ.nrbzIJz99Om7TvJ04jnSTmhvlM7aR9hMM1Aqjp2ONJ1UKYCvegBLrTu6cYR968_OpmnAGJ8vkd7sIjUjtR4zbw"`,                                                                                                                                                                           // gitleaks:allow
		`https://dai2-playlistserver.aws.syncbak.com/cpl/20980038/dai2v5/1.0/7b2264657669636554797065223a387d/master.m3u8?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkdyYXkyMDE2MDgyOSJ9.eyJtaWQiOiIyMDk4MDAzOCIsImNpZCI6MjE5MDMsInNpZCI6MTU4LCJtZDUiOiIwN2QxMmRjNjAwOTM2MGI0MmY3NjNkNTRiMWIwZjI1NCIsImlhdCI6MTY2MDkxMzU2MCwiZXhwIjoxNjkyNDQ5NTYwLCJpc3MiOiJTeW5jYmFrIChURykifQ.JrWVgwzIn_RcNuWhkzIjr1i4qjXU1v4n0KFrSzoTQvQ`,                                                                                                                                                                                                                                                                                                  // gitleaks:allow		`
		`"SessionToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NLZXkiOiI2TjJCQUxYN0VMTzgyN0RYUzNHSyIsImFjciI6IjAiLCJhdWQiOiJhY2NvdW50IiwiYXV0aF90aW1lIjoxNTY5OTEwNTUyLCJhenAiOiJhY2NvdW50IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJleHAiOjE1Njk5MTQ1NTQsImlhdCI6MTU2OTkxMDk1NCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL2F1dGgvcmVhbG1zL2RlbW8iLCJqdGkiOiJkOTk4YTBlZS01NDk2LTQ4OWYtYWJlMi00ZWE5MjJiZDlhYWYiLCJuYmYiOjAsInBvbGljeSI6InJlYWR3cml0ZSIsInByZWZlcnJlZF91c2VybmFtZSI6Im5ld3VzZXIxIiwic2Vzc2lvbl9zdGF0ZSI6IjJiYTAyYTI2LWE5MTUtNDUxNC04M2M1LWE0YjgwYjc4ZTgxNyIsInN1YiI6IjY4ZmMzODVhLTA5MjItNGQyMS04N2U5LTZkZTdhYjA3Njc2NSIsInR5cCI6IklEIn0._UG_-ZHgwdRnsp0gFdwChb7VlbPs-Gr_RNUz9EV7TggCD59qjCFAKjNrVHfOSVkKvYEMe0PvwfRKjnJl3A_mBA",`, // gitleaks:allow
		`2020/11/04 21:08:40 Access Token:
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTAwYzI3ZDEtYjVhYS00NjU0LWFmMTYtYjExNzNkZTY1NjI5Iiwicm9sZXMiOlsiYWRtaW4iXSwiaWF0IjoxNjA0NTE2OTIwLCJleHAiOjE2MDQ1MTc4MjAsImp0aSI6IjYzNmVmMDc0LTE2MzktNGJhZi1hNGNiLTQ4ZDM4NGMxMzliYSIsImlzcyI6Im15YXBwIn0.T9B0zG0AHShO5JfQgrMQBlToH33KHgp8nLMPFpN6QmM"`, // gitleaks:allow
		`"idToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik56azVNREl5TVRnNFJqWTBORGswT0VJM1JrRXpORGN4UmtVMU1FWXdNemczT1VKQlFqRTBNZyJ9.eyJuaWNrbmFtZSI6InRlc3QtaW50ZXJhY3RpdmUtY2xpIiwibmFtZSI6IlRlc3RpbmcgSW50ZXJhY3RpdmUgQ2xpIiwicGljdHVyZSI6Imh0dHBzOi8vaW50ZXJhdGNpdmUuY2xpL3Rlc3RpbmcucG5nIiwidXBkYXRlZF9hdCI6IjIwMTktMDktMTZUMTU6MTg6NDMuOTk5WiIsImVtYWlsIjoidGVzdGluZ0BpbnRlcmFjdGl2ZS5jbGkiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9zZXJ2ZXJsZXNzaW5jLmF1dGgwLmNvbS8iLCJzdWIiOiJ0ZXN0LWludGVyYWN0aXZlLWNsaSIsImF1ZCI6IlhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYIiwiaWF0IjoxNTYwMDAwMDAwLCJleHAiOjMwMDAwMDAwMDB9.GcNQtWSxv9CHTABw-HIjYSvRxTEapDUDqIIWRGmz01XmShQxRGOHRuUg1NKU4w9MpOlB6txHKs8UWd2eZkzw_Z4QmIuLyAVhVklpWP2-xeysPLUyqVTgqAg8kgIUAwdKjmrdpQqHhGd-Q1BIX62-E-qKKx8prmADSw_hgmuvlMuSCa1ajCnfyUXycQxDmbFrvjd24lJER0FSpB2nWWW3KxZ_UBX-TuVmiEtRXg9GYeSv6oIU78PrIhYgJ0QjERRF1yAYamIXNRs-KZ7Z4YiFNC4uKzFH1524pZkS4Q0-pweIvBrrsjekz-vEYcbaVG1zAxDu_yNrYPk5phCy8MHTrQ",`, // gitleaks:allow
		`TokenIssuer1WithAzp = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRUX3c5TFJOclk3d0phbEdzVFlTdDdydXRaaTg2R3Z5YzBFS1I0Q2FRQXciLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJiYXIiLCJleHAiOjQ3MzQxMjU0NTMsImlhdCI6MTU4MDUyNTQ1MywiaXNzIjoidGVzdC1pc3N1ZXItMUBpc3Rpby5pbyIsInN1YiI6InN1Yi0xIn0.SO4qjRJPYItkpGGpCDfEhaUfdthO8L9b_aawao4dJKyqqXN0uYdsJau_JZzyPQ1emAmJP7VyjwELrlszA6xV65na_O-eny23iwhEoroChQMpcr9DWqSUBUfpbHSPFAjUv38SUbQfLgar0HrMxQlTAzB0vyzn2g6-cukP469ZlOUmzvi9b4UpolTLp_WPgEHKjZw8CL56CcuJqBIKgfn0M7ta2bY_qx-UrsEW0CqnXol7vhXuDAfMeWZYKuDP8qc2VH1T6wpO2JnZ0EaNDuZfQLOWFYKsFGlaYcus9j462AfJQBSFQTbkIjkvKMK6aI_rMEesAnJr2eei1UYi14JYiQ"`,                                                                                                                                                                                                                                                                                                                                                                      // gitleaks:allow
		`eyJhbGciOiJSUzI1NiIsImtpZCI6IkRIRmJwb0lVcXJZOHQyenBBMnFYZkNtcjVWTzVaRXI0UnpIVV8tZW52dlEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjM1MzczOTExMDQsImdyb3VwcyI6WyJncm91cDEiLCJncm91cDIiXSwiaWF0IjoxNTM3MzkxMTA0LCJpc3MiOiJ0ZXN0aW5nQHNlY3VyZS5pc3Rpby5pbyIsInNjb3BlIjpbInNjb3BlMSIsInNjb3BlMiJdLCJzdWIiOiJ0ZXN0aW5nQHNlY3VyZS5pc3Rpby5pbyJ9.EdJnEZSH6X8hcyEii7c8H5lnhgjB5dwo07M5oheC8Xz8mOllyg--AHCFWHybM48reunF--oGaG6IXVngCEpVF0_P5DwsUoBgpPmK1JOaKN6_pe9sh0ZwTtdgK_RP01PuI7kUdbOTlkuUi2AO-qUyOm7Art2POzo36DLQlUXv8Ad7NBOqfQaKjE9ndaPWT7aexUsBHxmgiGbz1SyLH879f7uHYPbPKlpHU6P9S-DaKnGLaEchnoKnov7ajhrEhGXAQRukhDPKUHO9L30oPIr5IJllEQfHYtt6IZvlNUGeLUcif3wpry1R5tBXRicx2sXMQ7LyuDremDbcNy_iE76Upg`,                                                                                                                                                                                                                                                                                                         // gitleaks:allow
		`python examples/cli.py eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo`,                     // gitleaks:allow
		`"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZTpib2IifQ.HcfCW67Uda-0gz54ZWTqmtgJnZeNem0Q757eTa9EZuw"`,                                                                           // gitleaks:allow
		`"value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODk1ODU1NjN9.PtfDS1niGoZ7pV6kplI-_q1fVKLnknQ3IwcrLZhoVCU",`,                                                                                        // gitleaks:allow
		`//                  authorization: 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU3Njk5Njc5OSwiZXhwIjoxNTg0ODU5MTk5fQ.eyJ1aWQiOjQ1NzQyN30.0ei5UE6OgLBzN2_IS7xUIbIfW_S1Wzl42q2UeusbboxuzvctO_4Mz6YRr6f0PBLUVZMETxt8F0_4-yqIJ3_kUQ',`, // gitleaks:allow
		`eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJpc3Rpby1jbmktdG9rZW4tcGpwYnciLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiaXN0aW8tY25pIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZmY2MDY0ODAtY2MxMC0xMWU4LTkxYzctMDAwYWY3MGE5YmE4Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmlzdGlvLWNuaSJ9.0YHfuEwYn6tbtgy1YOhOjEtuQ8TnvmA_1RkuggfVGigMpCMGoOkIWwxpeDVXZm7dNwRmQVwLhchA3MeXz0QGRmStLa-VncedkmPOGSC-FyPvPybhZI53w3nhIVU3Vkh9_s-E2H2zFTwRQthxlDAlldNqEHpM9fINIVs0Z3bAogz2DYHwerSOtfZU-6d8b5nn73gnNhl6zBJ_0qg22SZjc6TrDYk--WwjUbU5_OIW6YxEmFnNVqfSeCrpg18IiJCsB0XRkixgu46Ev63jsrJ1vi41PVvBN79X7F-SiNNwTqwACRZvlX1zRw_GV7o4iPvnKn685WLOyMfoB5K6hSxrpQ`,                                                                                       // gitleaks:allow
		`const TestKubernetesJWT_A = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImFkbWluLXRva2VuLXFsejQyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiNzM4YmMyNTEtNjUzMi0xMWU5LWI2N2YtNDhlNmM4YjhlY2I1Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6YWRtaW4ifQ.ixMlnWrAG7NVuTTKu8cdcYfM7gweS3jlKaEsIBNGOVEjPE7rtXtgMkAwjQTdYR08_0QBjkgzy5fQC5ZNyglSwONJ-bPaXGvhoH1cTnRi1dz9H_63CfqOCvQP1sbdkMeRxNTGVAyWZT76rXoCUIfHP4LY2I8aab0KN9FTIcgZRF0XPTtT70UwGIrSmRpxW38zjiy2ymWL01cc5VWGhJqVysmWmYk3wNp0h5N57H_MOrz4apQR4pKaamzskzjLxO55gpbmZFC76qWuUdexAR7DT2fpbHLOw90atN_NlLMY-VrXyW3-Ei5EhYaVreMB9PSpKwkrA4jULITohV-sxpa1LA"`,                                                                                   // gitleaks:allow
		`string: grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJkZXYtdG8tYW5hbHl0aWMtYXBpLW1hYy10ZXN0QGRldnRvLTE3NTQxOS5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImF1ZCI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92NC90b2tlbiIsImV4cCI6MTUxOTIyOTAxOSwiaWF0IjoxNTE5MjI4ODk5LCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvYW5hbHl0aWNzLnJlYWRvbmx5In0.V8CSfSS7sKfoE5857jE9WDrGFHF1CyRr3cZpdUv9MjaaTcPRSLuNxB8yrxRP_7hNmlRgx_KdUzBgDJp3M_9tU4rZgFaIC7-bctvz_0rqbnMqSTniHYNGo7w__zO0bRaTpR3ILOfoxCQLcVC-tA4eCIMzRCznkY0VAaoLM7K-hnwQz6fCqSF31fmOwzAdVBPi5qnMETogh_7SiHn4WNUYI0FQf5SFLhcCbBZtORcbANe9hXp9po2P-VTBqs6u9dAZw5kZ2c1l5zbzrjYp5VcYl1XQFQTxP2zgMxhpX3k1UH9ObggOMUxvASyLbPZ7viOPKRlFxkAAHPTN2N1FYbpVeA`,                                                                                                                                                                                             // gitleaks:allow
		`eyJhbGciOiJSUzI1NiIsImtpZCI6IlM1WGxrRnVIclJRaEVDbmg3cndZZFVTRTFpT0lfQzZsZ2NXbHZoOS1pbVUifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi11c2VyLXRva2VuLWo1a3B2Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluLXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiJiZTZjZmUwZS0yYzFhLTRkNTYtYmVkMC1jYWRmYjYxNzA1N2YiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZXJuZXRlcy1kYXNoYm9hcmQ6YWRtaW4tdXNlciJ9.LaBPEh6Qantd8tAc0X5DY9dDwUqZpxu38FHnp9TSJw-ghs3TsjrscFulUeEAtp2ng3ElLcU4SbNKPGJflF2dyW9Tmfn-Kt_6Jwq8HQ9GOCwAicEz0JVireHA7EWhATzuT56eO6MTe-2j5bpGnPQRJJtQ8AbtAN3nVK7RPjSzmc8Ppqx1z5i4oCGwiyRlGwqT-FkCtQLbQaQ4XmrASQoN4pJ_OBy5slztUhk32HdGP6pQx5c-nfei-of_4ij_fHrP0xEEfmVVvXqi9WKv1PLkQ3qTiSFDzv8M2sE4T6XmCGBbw7gyHzEGSpOAPZr00bX_YMCUvEF0lyP4YK696xWCBA`, // gitleaks:allow
		`$ curl "http://admin:password@127.0.0.1:8080/api/v2/token"
		{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYxMzMzNTI2MSwianRpIjoiYzBrb2gxZmNkcnBjaHNzMGZwZmciLCJuYmYiOjE2MTMzMzQ2MzEsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiYUJ0SHUwMHNBUmxzZ29yeEtLQ1pZZWVqSTRKVTlXbThHSGNiVWtWVmc1TT0iLCJ1c2VybmFtZSI6ImFkbWluIn0.WiyqvUF-92zCr--y4Q_sxn-tPnISFzGZd_exsG-K7ME","expires_at":"2021-02-14T20:41:01Z"}`, // gitleaks:allow
		`curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYxMzMzNTI2MSwianRpIjoiYzBrb2gxZmNkcnBjaHNzMGZwZmciLCJuYmYiOjE2MTMzMzQ2MzEsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiYUJ0SHUwMHNBUmxzZ29yeEtLQ1pZZWVqSTRKVTlXbThHSGNiVWtWVmc1TT0iLCJ1c2VybmFtZSI6ImFkbWluIn0.WiyqvUF-92zCr--y4Q_sxn-tPnISFzGZd_exsG-K7ME" "http://127.0.0.1:8080/api/v2/dumpdata?output-data=1"`,                                                                                                                                                                                                                                                                                                                                                                                                                                        // gitleaks:allow
		`"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxNjQxMDgxNTM5fQ.K5DnnbbIOspRbpCr2IKXE9cPVatGOCBrBQobQmBmaeU"`,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             // gitleaks:allow
		`{"signatures": [ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlcyI6W3sibmFtZSI6Ii5tYW5pZmVzdCIsImhhc2giOiJjMjEzMTU0NGM3MTZhMjVhNWUzMWY1MDQzMDBmNTI0MGU4MjM1Y2FkYjlhNTdmMGJkMWI2ZjRiZDc0YjI2NjEyIiwiYWxnb3JpdGhtIjoiU0hBMjU2In0seyJuYW1lIjoicm9sZXMvYmluZGluZ3MvZGF0YS5qc29uIiwiaGFzaCI6IjQyY2ZlNjc2OGI1N2JiNWY3NTAzYzE2NWMyOGRkMDdhYzViODEzNTU0ZWJjODUwZjJjYzM1ODQzZTcxMzdiMWQifV0sImlhdCI6MTU5MjI0ODAyNywiaXNzIjoiSldUU2VydmljZSIsImtleWlkIjoibXlQdWJsaWNLZXkiLCJzY29wZSI6IndyaXRlIn0.ZjtUgXC6USwmhv4XP9gFH6MzZwpZrGpAL_2sTK1P-mg"]}`,                                                                                                                                                                                                                                                                                                             // gitleaks:allow
		`"id_token": "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJQb0VnWFA2dVZPNDVJc0VOUm5nRFhqNUF1NVlhIiwiYXpwIjoiUG9FZ1hQNnVWTzQ1SXNFTlJuZ0RYajVBdTVZYSIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUzNDg5MTc3OCwiaWF0IjoxNTM0ODg4MTc4LCJqdGkiOiIxODQ0MzI5Yy1kNjVhLTQ4YTMtODIyOC05ZGY3M2ZlODNkNTYifQ.ELZ8ujk2Xp9xTGgMqnCa5ehuimaAPXWlSCW5QeBbTJIT4M5OB_2XEVIV6p89kftjUdKu50oiYe4SbfrxmLm6NGSGd2qxkjzJK3SRKqsrmVWEn19juj8fz1neKtUdXVHuSZu6ws_bMDy4f_9hN2Jv9dFnkoyeNT54r4jSTJ4A2FzN2rkiURheVVsc8qlm8O7g64Az-5h4UGryyXU4zsnjDCBKYk9jdbEpcUskrFMYhuUlj1RWSASiGhHHHDU5dTRqHkVLIItfG48k_fb-ehU60T7EFWH1JBdNjOxM9oN_yb0hGwOjLUyCUJO_Y7xcd5F4dZzrBg8LffFmvJ09wzHNtQ",`, // gitleaks:allow
		`      # The following default key is generated by the local Supabase start and doesn't change
		- SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0`, // gitleaks:allow
		`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoyLCJjIjozfQ.hxhGCCCmGV9nT1slief1WgEsOsfdnlVizNrODxfh1M8`, // gitleaks:allow
		`--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhY3RvclR5cGUiOiJVU0VSIiwiYWN0b3JJZCI6ImRhdGFodWIiLCJ0eXBlIjoiUEVSU09OQUwiLCJ2ZXJzaW9uIjoiMSIsImV4cCI6MTY1MDY2MDY1NSwianRpIjoiM2E4ZDY3ZTItOTM5Yi00NTY3LWE0MjYtZDdlMDA1ZGU3NjJjIiwic3ViIjoiZGF0YWh1YiIsImlzcyI6ImRhdGFodWItbWV0YWRhdGEtc2VydmljZSJ9.pp_vW2u1tiiTT7U0nDF2EQdcayOMB8jatiOA8Je4JJA' \`,                                                                                                                                                                                                          // gitleaks:allow
		`"Cookie": "auth-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NDIxMTEsImlzQWRtaW4iOmZhbHNlLCJnaXRodWJJZCI6ImR5ZXhwbG9kZSIsImFwcFJvbGVzIjpbInVzZXIiXSwicm9sZXMiOnsiNDciOiJzdHVkZW50IiwiNTYiOiJzdHVkZW50In0sImNvdXJzZXNSb2xlcyI6eyI0NyI6WyJzdHVkZW50Il0sIjU2IjpbInN0dWRlbnQiXX0sImNvdXJzZXMiOnsiNDciOnsibWVudG9ySWQiOm51bGwsInN0dWRlbnRJZCI6NjY3OTMsInJvbGVzIjpbInN0dWRlbnQiXX0sIjU2Ijp7Im1lbnRvcklkIjpudWxsLCJzdHVkZW50SWQiOjYzMzk4LCJyb2xlcyI6WyJzdHVkZW50Il19fSwiaWF0IjoxNjQ1MjA5NzI2LCJleHAiOjE2NDUzODI1MjZ9.btpYeSioEDUNMI6bAPqgu5zndA8XR5DT8P9U9kotOEA",`, // gitleaks:allow
		`<li> <a class="cbtn btn-grad-s btn-shadow btn-width"
		target="_blank"
		href="https://demo.kuboard.cn/dashboard?k8sToken=eyJhbGciOiJSUzI1NiIsImtpZCI6InZ6SzVqZFNJOXZFMmxQSkhXamNBcFY4RU9FR0RvSUR5bzJIY0NwVG1zODQifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJrdWJvYXJkLXZpZXdlci10b2tlbi0yOW40cyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJrdWJvYXJkLXZpZXdlciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjQzMWMwNmYyLTNiNTAtNGEyMy1hYjM1LTkyNDQwNTQ2NzFkZCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTprdWJvYXJkLXZpZXdlciJ9.kgwTa6t00gNC0vgr6HOvCqkDghPcW-jVDg-_K6WLy97ppb9jvaqVz-AxXzF7mJqXnNetbJw-8-x_L3ogSsDlTKmRucao96VA2tPKxel8pM04J8MU0ZmYgWhTJelibbxmQK3jwGM4x32bckOOvmtumcXdsBRN0z1SZ1iu4H0VoaswhfoFS4ZJKoe61xyqoDhQx4RLCVJh_-Uctd5RCcPLWFEk-BHqC8vUTy8QcRst6RIIozQdTqsv7Xs6bH6dHrHFS--eVVTH2orQdm8znuUFhlqFOOjmCIMzIlaUQC_SO9URIGYOs0jrk27N9KC0HvQ5dLgFmwyNJ0Gu7cYi23NP1A">
		在线演示</a></li>`, // gitleaks:allow
		`eyJhbGciOiJSUzI1NiIsImtpZCI6IlM1WGxrRnVIclJRaEVDbmg3cndZZFVTRTFpT0lfQzZsZ2NXbHZoOS1pbVUifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi11c2VyLXRva2VuLWo1a3B2Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluLXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiJiZTZjZmUwZS0yYzFhLTRkNTYtYmVkMC1jYWRmYjYxNzA1N2YiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZXJuZXRlcy1kYXNoYm9hcmQ6YWRtaW4tdXNlciJ9.LaBPEh6Qantd8tAc0X5DY9dDwUqZpxu38FHnp9TSJw-ghs3TsjrscFulUeEAtp2ng3ElLcU4SbNKPGJflF2dyW9Tmfn-Kt_6Jwq8HQ9GOCwAicEz0JVireHA7EWhATzuT56eO6MTe-2j5bpGnPQRJJtQ8AbtAN3nVK7RPjSzmc8Ppqx1z5i4oCGwiyRlGwqT-FkCtQLbQaQ4XmrASQoN4pJ_OBy5slztUhk32HdGP6pQx5c-nfei-of_4ij_fHrP0xEEfmVVvXqi9WKv1PLkQ3qTiSFDzv8M2sE4T6XmCGBbw7gyHzEGSpOAPZr00bX_YMCUvEF0lyP4YK696xWCBA`,                                                                                                                                                              // gitleaks:allow
		`eyJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6IlRlc3QiLCJsb2dnZWQtaW4tdXNlciI6eyJzY29wZWRQZXJtaXNzaW9uIjpbXSwicGVybWlzc2lvbnMiOlsiQS5hZG1pbl9jdXN0b21lcl9kZWxldGUiLCJBLm5vcm1hbF91c2VyX2FwcCIsIkEubm9ybWFsX3VzZXJfY29uZmlndXJhdGlvbiIsIkEubm9ybWFsX3VzZXJfd2VsY29tZV9jb250cm9scyIsIkEubm9ybWFsX3VzZXJfb3JkZXIiLCJBLm5vcm1hbF91c2VyX3NlYXJjaCIsIkEubm9ybWFsX3VzZXJfc2VhcmNoX3BjIiwiQS5ub3JtYWxfdXNlcl9zZWFyY2hfcHJpdmF0ZSIsIkEubm9ybWFsX3VzZXJfcHJpY2luZyIsIkEubm9ybWFsX3VzZXJfcHJpdmF0ZSIsIkEubm9ybWFsX3VzZXJfY29tbWVyY2lhbCIsIkEubm9ybWFsX3VzZXJfcGMiXSwibmFtZSI6WyJUZXN0Il0sIm1haWwiOlsiVGVzdEBleGFtcGxlLmNvbSJdLCJvcmdhbml6YXRpb24iOlsiWC1YeHh4eHguMTIzNCJdLCJsb2NhdGlvbiI6WyIxMjMyMSJdLCJ1bml0IjpbIjEwMyJdLCJjb3VudHJ5IjpbIkNOIl0sInVzZXJUeXBlIjoiZW1wbG95ZWUifSwiaWRlbnRpdHktaWQiOiJNb2NrIn0.EK5TbwsIgde3mT3n7NK2W7TCvpgQQLzshvPPANRQeUmKOv2AWbo_7vNEDTSkwUlaHRN3-dknv8F95p5MsGTzH6Uva8aOPJG6JdBIoYX_ud3aBN-hY1i2Xpf8pqjeINfY3_gDNAB9gdMznEej2uqhPwUXmZtcuWPdUCCeNqPJbRUAJeVXxLr_JtQzO2jmuwNY_YYp7KaEIANZwG1spvLuIGZ0HA03u8ye9c2lfqYcjgfIkjMrwgWPamR7joZOZPdQSO2EHrF7bUWMjRNY-FF5V7tOjEijkknE_nDq5THcEvx1seHYFdFNwy9LSSGGPVmZMKTKQ3UUlZZyBMXcOpOA9w`, // gitleaks:allow
		// TODO: Detect newlines or escapes (\)?
		// https://github.com/mongodb/mongo/blob/1960b792ade4e179ddc6113a3cd400e9492ca11d/src/mongo/crypto/README.JWT.md?plain=1#L115-L117
		// TODO: Detect empty claims section?
		// `eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0Iiwia2V5X29wcyI6W10sImV4dCI6dHJ1ZSwieCI6IllUcEY3bGtTc3JvZVVUVFdCb21LNzBTN0FhVTJyc0ptMURpZ1ZzbjRMY2F5eUxFNFBabldkYmFVcE9jQVV5a1ciLCJ5IjoiLU5pS3loUktjSk52Nm02Z0ZJUWc4cy1Xd1VXUW9uT3A5dkQ4cHpoa2tUU3U2RzFlU2FUTVlhZGltQ2Q4V0ExMSJ9LCJhcHUiOiIiLCJhcHYiOiIifQ`,
		`String tokenWithNoneAlg = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.";`,                                                                               // gitleaks:allow
		`# Req: Invoke-RestMethod -Uri 'http://localhost:8085/users' -Headers @{ 'X-API-KEY' = 'eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6Im1vcnR5Iiwic3ViIjoiMTIzIn0.' }`, // gitleaks:allow
	)
	fps := []string{}
	return utils.Validate(r, tps, fps)
}

func JWTBase64() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "jwt-base64",
		Description: "Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information.",
		Regex: regexp.MustCompile(
			`\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}`),
		Entropy:  2,
		Keywords: []string{"zxlk"},
	}

	tps := generateTestValues()
	fps := []string{
		`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2
Comment: GPGTools - https://gpgtools.org

mQENBFOrMNcBCAC+gLI4s3bUkobS5NpOQbWfjWXbqC0Ixpc5bZYDOvsmfstmswna
UWUXkRH9RONabzrAu4TGvW0f5DkC2fuWWHJhZWEccn+VE83+avMZN4/mzldSXPNX
A6F7+wHb1DjG+FCDcxMghkwDjGc16LOtZGufUo5iRQaC5pmNBOgDWdiObGPKOTEL
/uU8zLtKi2cibbkhRm22IGOzGyZMZN6zvEtPzlCp3eZEGMW0Ig+kbl6SaSDrSJNK
wElYcr/kJ9QF6CQ2iwZCGeL2jH5QaOi5uj1LXONpCd9nPeyDXc+Z20gXZiqkwRLc
IBPKza6hq/+4nwHBq8DNLv0W4xNC59jLbIhpABEBAAG0LEZyYW5rIE5vdGhhZnQg
PGZub3RoYWZ0QGFsdW1uaS5zdGFuZm9yZC5lZHU+iQE9BBMBCgAnBQJTqzDXAhsD
BQkHhh+ABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJECqYOYG1w7FJOr4IAK8x
ec4jbjd6jkKe0YJGdPzg6TM73ISV5VrUlJX7O3jgxHB4M8KIHN/8A/+ZxLk7WM96
iq0C8atWHkCkQBtNduWhzAFccQlpxrrb18T5/oItcrmX9Dx2H5WeIl4WAoqe0MTk
iMPv29RMMH9RJvXL0ihuuH4Z0VxV5nurI9QmGzG69QOzfP9qY1EfQEceO7OqXXvY
vvBEUbmWshLuHJ6tOQY5ib3+aLO7m+yJTgJ7s6DHBDqLhqJPW0g7jiJcrDhYXsoS
JMMhMdUhckeZfTXm1N3Dc+/t9/E8NZjdZ2q/ZZzvygC4mu0uihwBKFqoFvXCHRaW
Rf4uYxE+/Upna/mbXQi5AQ0EU6sw1wEIALSp9Cc4t/F2k+rwEfEMXihXLcLM9Dmh
ukz++kMSCSuq4QHE+I4rLda/lVSNJCXaXrGVkzJuzmpEeQFdhr6nLW9ZYhzK8FIc
YyfsYTQxXUVf5W4e/XfKNoG9lrwQd5XHxJTBJ57XjjoWJYPQ69NWH8622foOBpux
xewgR2LEFgl+ksu7aQL4cQif6D3dko3EiIf1t0LDBXxFEREFCg+vkDFsDIW5bdaI
mDYwewGj7dAPLuo0sx1We+uBxb+j30xw/ASDOBhO3ratQWs+4w2FC7gw7cuf0CJC
/hMEw8nloGsIbqBmAnLdlQBxkfFG9DqRBNdSUM8xI66F0eGaaPHJ/S8AEQEAAYkB
JQQYAQoADwUCU6sw1wIbDAUJB4YfgAAKCRAqmDmBtcOxSZvvB/4w6S5YZQUmDVYK
9HPOm49qWxGPd5dLHr2g388sJ4LDK98Q9oicHgf2R35OXTyqhv4kFJL3eukQ6oLW
QOqQKLRycrQUu7eSESAiVmJ1gbuXLAWJmvUABGSYzj3BjWQRexYW/MZ51XqNftF9
oOSAoFWrdqeJbHoxPTXIb6P8EWk4Ei2j2bSIfBBSbBMSB6Kfk9IjpISM8+97RS5o
6605rmM5MY1Lz8cq8AZIYJs/MnUCZrpQ0c9QSWrflHAeWAy6xMGfdSynbEExQ4z8
AIfKWMro74nRFbAnv/BzrF2R8uHmdE7T6q9ZZsAydlaxQbdmyhCeGAdw93CwAypb
vHVobJ8A
=mIC1
-----END PGP PUBLIC KEY BLOCK-----`,
	}
	return utils.Validate(r, tps, fps)
}

func generateTestValues() []string {
	// Sample JWT from RFC-7519
	jwtSuffix := ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Validate known header parameters
	// https://www.iana.org/assignments/jose/jose.xhtml
	headers := map[string][]string{
		"alg": {
			`"ES256"`,
			`"ES384"`,
			`"ES512"`,
			`"ECDH-ES"`,
			`"HS256"`,
			`"HS384"`,
			`"HS512"`,
			`"RS256"`,
			`"RS384"`,
			`"RS512"`,
			`"PS256"`,
			`"PS384"`, `"PS512"`,
			`"none"`,
			// Nonstandard
			`"A128KW"`,
			`"ECDH-ES+A256KW"`,
			`"RSA-OAEP"`,
		},
		"apu":     {`"Tx9qG69ZfodhRos-8qfhTPc6ZFnNUcgNDVdHqX1UR3s"`, `"RfXdxTfIzilWBzWWX3ovHBDzgDcLNy0BFJWSxa0dqnw"`},
		"apv":     {`"ZGlkOmVsZW06cm9wc3RlbjpFa"`, `"ZGlkOmtleTp6Nk1rak1TWWF1dU1neDlhekV5VW5UVzVvNWpGUmtiQnU1VDgzZjM5dU53bnNHbW0jejZMU29HdFpTclVNWnVkQWFnekVmWWY3azhqSFpjR0Q3OVNveDd2NHdDa0RLTlN3"`},
		"aud":     {`"https://vault.example.com"`, `"http://example.com"`},
		"b64":     {`true`, `false`},
		"crit":    {`["exp"]`},
		"cty":     {`"example"`, `"json"`},
		"epk":     {`{"crv":"X25519","kty":"OKP","x":"Tx9qG69ZfodhRos-8qfhTPc6ZFnNUcgNDVdHqX1UR3s"}`, `{"kty":"OKP","crv":"X25519","x":"RfXdxTfIzilWBzWWX3ovHBDzgDcLNy0BFJWSxa0dqnw"}`},
		"enc":     {`"A256GCM"`, `"A256CBC-HS512"`, `"A128CBC-HS256"`},
		"jku":     {`"https://c2id.com/jwks.json"`},
		"jwk":     {`{"crv":"P-256","kid":"DB2X:GSG2:72H3:AE3R:KCMI:Y77E:W7TF:ERHK:V5HR:JJ2Y:YMS6:HFGJ","kty":"EC","x":"jyr9-xZBorSC9fhqNsmfU_Ud31wbaZ-bVGz0HmySvbQ","y":"vkE6qZCCvYRWjSUwgAOvibQx_s8FipYkAiHS0VnAFNs"}`, `{"kty":"RSA","n":"jyTwiSJACtW_SW-aiihQS5Y5QR704zUwjhlevY0oK-y5wP7SlIc2hq2OPVRarCzjhOxZl2AQFzM5VCR7xRDcnIn9t_pl7Mgsnx9hKDS9yQ24YXzhQ4cMEVVuqwcHvXqPdWDSoCZ1ccMqiiPyBSNGQTXMPY5PBxMOR47XwOb4eNMOPqnzVio3MEtL2wphtEonP3MY6pxJJzzel04wSCRZ4n06reqwER3KwRFPnRpRxAgmSEot5IBLIT3jj-amT5sD7YoUDbPmLk23zgDBIhX88fkClilg1W-fUi1XxYZomEPGvV7OrE1yszt4YDPqKgjJT8t2JPy__1ri-8rZgSxn5Q","e":"AQAB"`},
		"iss":     {`"http://localhost:8087/realms/grafana"`, `"kubernetes/serviceaccount"`},
		"iv":      {`"zjJPRrj0TGez9JYkChTrB3iqKoDkiBhn"`, `"10PlAIteHLVABtt"`},
		"kid":     {`"my_key_id"`, `"did:example:123#zC1Rnuvw9rVa6E5TKF4uQVRuQuaCpVgB81Um2u17Fu7UK"`},
		"key_ops": {`["sign"]`, `["decrypt"]`, `["encrypt"]`},
		"kty":     {`"EC"`, `"RSA"`},
		"nonce":   {`"Os_sBjfWzVZenwwjvLrwXA"`, `"LDDZAGcBuKYpuNlFTCxPYw"`},
		"p2c":     {`4096`, `1000`},
		"p2s":     {`"c_ORk4HSsqZD2LvVeCUHqg"`},
		"ppt":     {`"foo"`},
		"sub":     {`"project_path:my-group/my-project:ref_type:branch:ref:feature-branch-1"`, `"1234567890"`},
		// I cannot find any real-world examples of the svt header
		// and the RFC doesn't seem to explicitly state the content.
		"svt":      {``},
		"tag":      {`"h6mJqHn33oCsDd5X57MI-g"`},
		"typ":      {`"JWT"`, `"JWK"`, `"JSOE"`, `"JSON"`, `"plain"`},
		"url":      {`"https://example.com"`},
		"use":      {`"enc"`, `"sig"`},
		"ver":      {`"2"`, `"3"`},
		"version":  {`"2"`, `"3"`},
		"x5c":      {`["MIICmzCCAYMCBgF4HR7HNDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzEwMTcwOTE5WhcNMzEwMzEwMTcxMDU5WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCpLzXHp8i09R2HU5YJPyncC4tiAWWmaDrVZenqynWlWKOjIXb0Y5JoP3ET68u16Bf7mHQGc/u9rRvCw4A92HpJ15WyUSJ80YcK0gPTE0Woc1ZxdK3h4t9AoA8VSrROwQ77w/VAdGrrJ4bwkAVrFqSRpqAsW5XxV3/bU8YkVaG8mh0kuFf/5ib0vxdSkg+mz+ZCuIxQ5YN77kNaMecO19XuaBo7FsG9WjfCPxXYuajkuLgdptPgwTN4np70h0WjaSP/jhjL2ixf48w+27wFDP+ic+B/TCOtVa3fj1GPo6RLxHGU0Zh64jFhmvRM6E/kX7IQ+FJcOwp1VPA9/vMABopAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALILq1Z4oQNJZEUt24VZcvknsWtQtvPxl3JNcBQgDR5/IMgl5VndRZ9OT56KUqrR5xRsWiCvh5Lgv4fUEzAAo9ToiPLub1SKP063zWrvfgi3YZ19bty0iXFm7l2cpQ3ejFV7WpcdLJE0lapFdPLo6QaRdgNu/1p4vbYg7zSK1fQ0OY5b3ajhAx/bhWlrN685owRbO5/r4rUOa6oo9l4Qn7jUxKUx4rcoe7zUM7qrpOPqKvn0DBp3n1/+9pOZXCjIfZGvYwP5NhzBDCkRzaXcJHlOqWzMBzyovVrzVmUilBcj+EsTYJs0gVXKzduX5zO6YWhFs23lu7AijdkxTY65YM0="]`},
		"x5t":      {`"IYIeevIT57t8ppUejM42Bqx6f3I"`},
		"x5t#S256": {`"TuOrBy2NcTlFSWuZ8Kh8W8AjQagb4fnfP1SlKMO8-So"`},
		"x5u":      {`"https://tel.example.org/passport.cer"`},
		"zip":      {`"DEF"`},
	}

	var examples []string
	for key, values := range headers {
		for _, value := range values {
			header := fmt.Sprintf(`{"%s":%s}`, key, value)
			jwt := []byte(b64.RawURLEncoding.EncodeToString([]byte(header)) + jwtSuffix)
			examples = append(examples, b64.StdEncoding.EncodeToString(jwt))
			examples = append(examples, b64.RawStdEncoding.EncodeToString(jwt))
			examples = append(examples, b64.URLEncoding.EncodeToString(jwt))
			examples = append(examples, b64.RawURLEncoding.EncodeToString(jwt))
		}
	}
	return examples
}
