package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://fly.io/docs/security/tokens/
// https://github.com/trufflesecurity/trufflehog/pull/2381/files#r1565860579
// https://github.com/superfly/macaroon-elixir/blob/8b42043b0a24aada5c8b8eb8505dbf1590557f1b/test/vectors.json#L7
func FlyIOAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flyio-access-token",
		Description: "Uncovered a Fly.io API key", // TODO
		Regex:       utils.GenerateUniqueTokenRegex(`(?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3})`, false),
		Entropy:     4,
		Keywords:    []string{"fo1_", "fm1", "fm2_"},
	}

	// validate
	// fo1_
	tps := utils.GenerateSampleSecrets("fly", secrets.NewSecret(`fo1_[\w-]{43}`))
	tps = append(tps,
		`Fly access token: fo1_8rz-j7r2eqJ2U7affEOO3HJN0j63DInyog3eV-glQSc
`,
		`=============================================================================================================

fo1_BtKlzvfztw0M2hlLgTdsfPgDFiwM2jJjQXXy6I2pjuQ
fly deploy`)
	// fm1
	tps = append(tps, utils.GenerateSampleSecrets("fly", secrets.NewSecret(`fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}`))...)
	tps = append(tps,
		`ENV FLY_API_TOKEN="FlyV1 fm1r_lJPECAAAAAAAAMqcxBBLMJKXYKJiT0CI58XmukX/wrVodHlwczovL2FwaS5mbHkuaW8vdjGWAJLOAAFmXh8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDy5OfA2M6K6aLEoEDKxehojbj+8ZT9IrXCF5sL/r8m6/1gylwySsNxpD40wnpd/G2ZdjwVaQev1kEuFUgzERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry5AaXiroRdjrSsFExc/xRCDZKUA5GBzgATuNsfBZGCp2J1aWxkZXIfondnHwHEIMa6NWc4b52S+UY7vjPdwKrz00Uzrc1830mOHzQNLun7,fm1a_lJPERxPbtWHDNa+NYIZwbKN6b7/JxdbUprq0M10HI4fwtlxhqhdA/mMaMw70EC4TsfJyghIL98KP4ry4AaXiroRdjrSsFExc/xRCxBCVlAoRzKV/+qYkxuipIbIcw7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxlgSSzmS4Y7nPAAAAASCwgdcKkc4AAUktDMQQURck2h+upbiOrW66Nf5SA8QgrD03xlWju1WQi0AUhlk7YYFzOLDfhRyJ6nEziO37NUE="`,
	)
	// fm2
	tps = append(tps, utils.GenerateSampleSecrets("fly", secrets.NewSecret(`fm2_[a-zA-Z0-9+\/]{100,}={0,3}`))...)
	tps = append(tps,
		`#           FLY_API_TOKEN: FlyV1 fm2_lJPECAAAAAAAAyZtxBD1hSZ7L5leXsj64ZbDlkm/wrVodHRwczovL2FwaS5mbHkuaW8vdjGWAJLOAAwMDB8Lk7lodHRwczovL2FwaS5mbHkuaW8vYWFhL3YxxDwDnhgJj/ML/nRKMiAYgnvXfNacrGWffj5TdfgGY2LU0ZetT7WzTLQQMO8cN2nRTztl/xLjnnZg5pBwFonETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAiR273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwjw2SlAORgc4APu7vHwWRgqdidWlsZGVyH6J3Zx8BxCAlmLbu1HQDg8ZAGKKmEt4Mbnbqli6lbzBDHsawhcUF4A==,fm2_lJPETmhNA6Yl0X1tatt8ezA0UjVQiJr93VQ7qAmD5GG2Ce5txhbQv3tmIGsvaC7BOkIqAij273bhZkO44AYsrCPr2XF8W6Twk7NyU+3UUeDwj8QQbn07DOV+7SmoLj/uT+dbr8O5aHR0cHM6Ly9hcGkuZmx5LmlvL2FhYS92MZgEks5mqfbvzwAAAAE9PYz9F84AC7QACpHOAAu0AAzEEFfW3B+SzffV/KrAYa8qqpnEIIlD6DqZMZQ9Kt7fEenCCOLA+tUSJ+kmEFIUcc83npOI`,
		`"BindToParentToken": "FlyV1 fm2_lJPEEKnzKy0lkwV3B+WIlmrdwejEEFv5qmevHU4fMs+2Gr6oOiPC2SAyOTc0NWI4ZmJlNjBlNjJmZTgzNTkxOThhZWE4MjY0M5IMxAMBAgPEIH7VG8u74KwO62hmx8SZO8WaU5o1g3W2IVc7QN6T1VTr",`,
	)
	fps := []string{
		// fo1_
		`resource "doppler_integration_flyio" "prod" {
  name    = "TF Fly.io"
  api_key = "fo1_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}`, // https://github.com/DopplerHQ/terraform-provider-doppler/blob/a012e1a7903cce391be511b391850b29ebfdeb68/docs/resources/integration_flyio.md?plain=1#L17
		`pub const MINIDUMP_SYSMEMINFO1_PERF_CCTOTALDIRTYPAGES_CCDIRTYPAGETHRESHOLD: u32 = 4u32;`, // https://github.com/microsoft/windows-rs/blob/0f7466c34e774e547d21c579b58b60168c4ee6bc/crates/libs/sys/src/Windows/Win32/System/Diagnostics/Debug/mod.rs#L1258
		`<input type="hidden" name="authenticity_token" value="7SWa-Fo1_hsC6oovfBsJFLGPUl2EhkSWPbJhWANwgaJWBDl1vxd9VNqXTNAefsJqzIRYaZEfYZLffa31rw8zJA" autocomplete="off" />`,
		// fm1
		`signature":"I7l2ZXhw9ajjIE2w9tjHNvYjcHg7E2qldMMhoQKjborcWIj8c40rMj83venoy6gXsg6V6B7dlBWxUmzYJR3lJKGECtCSM5BqBvWhL6wX2CN2lZlvwNCyPjG4PCt5MAK1yV1Xv4fqfz8EfT_U49vOzfM1a_nfhXOzrvdg9XgLkAotWBI31vPKjMBrvPqiLcZ12MDNTSK7ubRpVaehSNxiGYHpLhWTkun9qm_APYYXJBjhJYkej50Qcp7Ou8fs3kH02prYIJt4JbWelr5vUDkgMH3AwEx1eYu5NI_8sESlqosl1nhSDx7zq3X1FV1iJlAYCNwGWzW1tjo8PCaJrIHVZZnhBPMN-6ahmOpKb8GViqd4fCQuNe4VUSOeJg8i97kMuk-4r7hwIubR0XfCGzxr7uGDQBdFANi3c4dLlzBAJNifa6b_hT4Xzqja6RCFSv6Cnalyx3hbSkjbyThnXFavJIiR7cvgTcdECg9VxkaxqqRhfAkLAS3hpXQAIYL_bw61M3LN37WHwdgxN_6yZhbSbOsYPmTxiWvdlDaCP_iaCgXgJNfdQ6kep_I89slynE9gdDZ6NSjFJH2Soml4pR6HnQKPjA3OpoTwPSmZjxXY5I78xvrRqRkjdnVzeufqG8LyA-sAEtC0G_312JOxV4GZINquPGk1qFx8WN59Rxw28Tg",`,
		// fm2
		`<p><span class="emoji">🗣️</span> Adobe illustrator软件基础精讲课程<br><br><span class="emoji">🏷️</span> <a href="https://t.me/abskoop/8565?q=%23%E8%AE%BE%E8%AE%A1%E5%B8%88">#设计师</a> <a href="https://t.me/abskoop/8565?q=%23%E8%B5%84%E6%BA%90">#资源</a> <a href="https://t.me/abskoop/8565?q=%23%E5%A4%B8%E5%85%8B%E7%BD%91%E7%9B%98">#夸克网盘</a><br><br><span class="emoji">👉</span> <a href="https://www.ahhhhfs.com/62409/" target="_blank" rel="noopener">https://www.ahhhhfs.com/62409/</a></p><img src="https://cdn5.cdn-telegram.org/file/uGoDMy0VXMbL1nki9OT0VbJYtfURvDNLurptsQVuhuzF45tNfm2_z5wgR7CnL7lTZ4bbotjXZtiLWvolNQqWBRFWkcidtzSyhWvta9yPB3E2uyvfJvGpditkaLVIiCCXt9BhFBEdgkXa8ODaM7geHK3pW0tmO_IViHBnG8VZqVfDpaQW0W9IRAUwGv2mPZWVRysPJyDSIuY9b-_3ElUml-Xlpm1r8EDcm9Q2WCTCOYur7Gmef4imQ5D-DLTviqmoONgQDLA10WVS3CApXBK4ADSjoIUeMck62owtjElSXnEYMaSGI_OE3B21QplsspPbPlXVUBScLfLOFb9tn-34tw.jpg" width="800" height="533" referrerpolicy="no-referrer">`,
	}
	return utils.Validate(r, tps, fps)
}
