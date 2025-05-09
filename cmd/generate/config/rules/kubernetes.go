package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// KubernetesSecret validates if we detected a kubernetes secret which contains data!
func KubernetesSecret() *config.Rule {
	// Only match basic variations of `kind: secret`, we don't want things like `kind: ExternalSecret`.
	//language=regexp
	kindPat := `\bkind:[ \t]*["']?\bsecret\b["']?`
	// Only matches values (`key: value`) under `data:` that are:
	// - valid base64 characters
	// - longer than 10 characters (no "YmFyCg==")
	//language=regexp
	dataPat := `\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))`

	// define rule
	r := config.Rule{
		RuleID:      "kubernetes-secret-yaml",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		Regex: regexp.MustCompile(fmt.Sprintf(
			//language=regexp
			`(?i)(?:%s(?s:.){0,200}?%s|%s(?s:.){0,200}?%s)`, kindPat, dataPat, dataPat, kindPat)),
		Keywords: []string{
			"secret",
		},
		// Kubernetes secrets are usually yaml files.
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					// Ignore empty or placeholder values.
					// variable: {{ .Values.Example }} (https://helm.sh/docs/chart_template_guide/variables/)
					// variable: ""
					// variable: ''
					regexp.MustCompile(`[\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:\{\{[ \t\w"|$:=,.-]+}}|""|'')`),
				},
			},
			{
				// Avoid overreach between directives.
				RegexTarget: "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(kind:(?s:.)+\n---\n(?s:.)+\bdata:|data:(?s:.)+\n---\n(?s:.)+\bkind:)`),
				},
			},
		},
	}

	// validate
	tps := map[string]string{
		"base64-characters.yaml": `
apiVersion: v1
kind: Secret
data:
	password: AAAAAAAAAAC7hjsA+H3owFygUv4w5B67lcSx14zff9FCPADiNbSwYWgE+O7Dhiy5tkRecs21ljjofvebe6xsYlA4cVmght0=`,
		"comment.yaml": `
apiVersion: v1
kind: Secret
metadata:
  name: heketi-secret
  namespace: default
data:
  # base64 encoded password. E.g.: echo -n "mypassword" | base64
  key: bXlwYXNzd29yZA==`,
		// The "data"-key is before the identifier "kind: Secret"
		"before-kubernetes.yaml": `apiVersion: v1
 data:
 	extra: YWRtaW46cGFzc3dvcmQ=
 kind: secret
 metadata:
	 name: secret-sa-sample
	 annotations:
	 	kubernetes.io/service-account.name: 'sa-name'`,
		"before-kubernetes.yml": `apiVersion: v1
data:
	password: UyFCXCpkJHpEc2I9
	username: YWRtaW4=
kind: Secret
metadata:
	creationTimestamp: '2022-06-28T17:44:13Z'
	name: db-user-pass
	namespace: default
type: Opaque`,
		"before-comment.yml": `apiVersion: v1
data:
	# the data is abbreviated in this example
	password: UyFCXCpkJHpEc2I9
	username: YWRtaW4=
kind: Secret
metadata:
	creationTimestamp: '2022-06-28T17:44:13Z'
	name: db-user-pass
	namespace: default
type: Opaque`,
		"before-quoted-1.yaml": `apiVersion: 'v1'
data:
	extra: 'YWRtaW46cGFzc3dvcmQ='
kind: 'Secret'
metadata:
	name: 'secret-sa-sample'
	annotations:
		kubernetes.io/service-account.name: 'sa-name'`,
		"before-quoted-2.yaml": `apiVersion: "v1"
data:
	extra: "YWRtaW46cGFzc3dvcmQ="
kind: "secret"
metadata:
	name: "secret-sa-sample"
	annotations:
		kubernetes.io/service-account.name: "sa-name"`,
		"before-multiline-literal.yaml": `apiVersion: v1
data:
  .dockercfg: |
    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=
metadata:
  name: secret-dockercfg
type: kubernetes.io/dockercfg
kind: Secret
`,
		"before-multiline-folded.yaml": `apiVersion: v1
data:
  .dockercfg: >
    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=
metadata:
  name: secret-dockercfg
type: kubernetes.io/dockercfg
kind: Secret`,
		// Sample Kubernetes Secret from https://kubernetes.io/docs/concepts/configuration/secret/
		// The "data"-key is after the identifier "kind: Secret"
		"after-kubernetes.yaml": `apiVersion: v1
kind: secret
data:
	extra: YWRtaW46cGFzc3dvcmQ=
metadata:
	name: secret-sa-sample
	annotations:
		kubernetes.io/service-account.name: 'sa-name'`,
		"after-kubernetes.yml": `apiVersion: v1
kind: Secret
metadata:
  name: ca-secret
type: Opaque
data:
  ca.pem: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR4RENDQXF5Z0F3SUJBZ0lVV3pqUDl5RUk0eHlRSnBzVHVERU4yV2ROaUFzd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2FERUxNQWtHQTFVRUJoTUNWVk14RHpBTkJnTlZCQWdUQms5eVpXZHZiakVSTUE4R0ExVUVCeE1JVUc5eQpkR3hoYm1ReEV6QVJCZ05WQkFvVENrdDFZbVZ5Ym1WMFpYTXhDekFKQmdOVkJBc1RBa05CTVJNd0VRWURWUVFECkV3cExkV0psY201bGRHVnpNQjRYRFRFMk1EZ3hNVEUyTkRnd01Gb1hEVEl4TURneE1ERTJORGd3TUZvd2FERUwKTUFrR0ExVUVCaE1DVlZNeER6QU5CZ05WQkFnVEJrOXlaV2R2YmpFUk1BOEdBMVVFQnhNSVVHOXlkR3hoYm1ReApFekFSQmdOVkJBb1RDa3QxWW1WeWJtVjBaWE14Q3pBSkJnTlZCQXNUQWtOQk1STXdFUVlEVlFRREV3cExkV0psCmNtNWxkR1Z6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3QkhNOGN6anc0Q1cKK05wbklhV012RzZlcVhtelNZT20vbHdaNUhOMnVLck9xaTNHYUUyTjFKd2tzcGRmMXNOUGFZMHdPR2xkbURIZgoxSnlyTW8rUFdLVUVjWko1WGE4Vm02d2I0MlpjczN3MEp5dlEzWFJjaDQyMFJRWGRKayszcmMybWRvSVRkL0lmCnZjWms0N0RzQTMrQU5QSUlSTzdWRmZpS1JNRFpTUDR1OThnVjI2eW1zbjc0TzFVKzNVUHR1TEFTVTFLck9FTk4KR01FWG0ydTJpdmVvbTJrbjFlZTZuM1hCR1o2bU52cUNPdWUxRXdza0gvWkhoUVh1UDgyV1U5dVk0aGVORnoyQwpBNmR0Q0Q0c3Z6eHc3ZFQ2cVhsV0ZIWUYrc3VLVDhXNkczd3NkOWxzV0ZVY0ZWL0lwaTVobEVaTWprNFNoY3RqCjdpYnlrRURKM1FJREFRQUJvMll3WkRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFqQWRCZ05WSFE0RUZnUVVOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3SHdZRFZSMGpCQmd3Rm9BVQpOdnhRZ3o5ZTNXS2VscU1KTmZXNE1KUHYzc0V3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUp1TUhYUms1TEVyCmxET1p4Mm9aRUNQZ29reXMzSGJsM05oempXd2pncXdxNVN6a011V3QrUnVkdnRTK0FUQjFtTjRjYTN0eSt2bWcKT09heTkvaDZoditmSE5jZHpYdWR5dFZYZW1KN3F4ZFoxd25DUUcwdnpqOWRZY0xFSGpJWi94dU1jNlY3dnJ4YwpSc0preGp5aE01UXBmRHd0eVZKeGpkUmVBZ0huSyswTkNieHdtQ3cyRGIvOXpudm9LWGk4TEQwbkQzOFQxY3R3CmhmdGxwTmRoZXFNRlpEZXBuTUYwY2g2cHo5TFV5Mkh1cnhrV2dkWVNjY2VNU0hPTzBMcG4xeVVBMWczOTJhUjUKWk81Zm5KMW95Vm1LVWFCeDJCMndsSVlUSXlES1ZiMnY1UXNHbnYvRHVTMDZhcmVLTmsvTGpHRTRlMXlHOHJkcwpacnZHMzNvUmtEbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
`,
		"after-comment.yml": `apiVersion: v1
kind: Secret
metadata:
	creationTimestamp: '2022-06-28T17:44:13Z'
	name: db-user-pass
	namespace: default
type: Opaque
data:
	# the data is abbreviated in this example
	password: UyFCXCpkJHpEc2I9
	username: YWRtaW4=
`,
		"after-quoted-1.yaml": `apiVersion: 'v1'
kind: 'Secret'
data:
	password: 'UyFCXCpkJHpEc2I9'
	username: 'YWRtaW4='
metadata:
	name: 'db-user-pass'
	namespace: 'default'
type: 'Opaque'`,
		"after-quoted-2.yaml": `apiVersion: "v1"
kind: "Secret"
data:
	password: "UyFCXCpkJHpEc2I9"
	username: "YWRtaW4="
metadata:
	name: "db-user-pass"
	namespace: "default"
type: "Opaque"`,
		"after-multiline-literal.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: secret-dockercfg
type: kubernetes.io/dockercfg
data:
  .dockercfg: |
    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=
`,
		"after-multiline-folded.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: secret-dockercfg
type: kubernetes.io/dockercfg
data:
  .dockercfg: >
    eyJhdXRocyI6eyJodHRwczovL2V4YW1wbGUvdjEvIjp7ImF1dGgiOiJvcGVuc2VzYW1lIn19fQo=`,
	}
	fps := map[string]string{
		"empty-quotes1.yml": `apiVersion: v1            
kind: Secret              
metadata:                 
  name: registry-auth-data
type: Opaque              
data:                     
  htpasswd: ''
`,
		"empty-quotes2.yml": `apiVersion: v1            
kind: Secret              
metadata:                 
  name: registry-auth-data
type: Opaque              
data:                     
  htpasswd: ""
`,
		"overly-permissive1.yaml": `apiVersion: v1            
kind: Secret              
metadata:                 
  name: registry-auth-data
type: Opaque              
data:                     
  htpasswd: {{ htpasswd }}
---                       
apiVersion: v1            
                          kind: ReplicationController`,
		"overly-permissive2.yaml": `apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-csrf
  namespace: kubernetes-dashboard
type: Opaque
data:
  csrf: ""

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-key-holder
  namespace: kubernetes-dashboard
type: Opaque
`,
		"overly-permissive3.yaml": ` kind: Secret
 target:
   name: mysecret
   creationPolicy: Owner

---

kind: ConfigMap
 data:
       conversionStrategy: Default
       decodingStrategy: None
       key: secret/mysecret
       property: foo
     secretKey: foo`,
		// https://github.com/gitleaks/gitleaks/issues/1644
		"wrong-kind.yaml": `apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: example
  namespace: example-ns
spec:
  refreshInterval: 15s
  secretStoreRef:
    name: example
    kind: SecretStore
  target:
    name: mysecret
    creationPolicy: Owner
  data:
    - remoteRef:
        conversionStrategy: Default
        decodingStrategy: None
        key: secret/mysecret
        property: foo
      secretKey: foo
`,
		"sopssecret.yaml": `apiVersion: isindir.github.com/v1alpha3
kind: SopsSecret
metadata:
    name: app1-sopssecret
    namespace: test
spec:
    suspend: false
    secretTemplates:
    -   name: ENC[AES256_GCM,data:W3PiZ6lD6bpfAdI=,iv:2qF98ZkchgfWF4tZo8fok6zY0ZLNRV3wFpl8n2iyC7I=,tag:FzoL+CZHkLEqfWKniRApBA==,type:str]
        labels:
            app: ENC[AES256_GCM,data:t9ujIQ==,iv:slZBpmKF+DOg/wVBWmq5iTqkRBZUMao0a3MdoxzJs3s=,tag:xJyhdJ4rn/cB/4mxHzmGig==,type:str]
        stringData:
            db-password: ENC[AES256_GCM,data:O+5l4g==,iv:c/dS4BCBMbnKsXYuzBuCuVQt8RV9bOv5HgdpL+iwmns=,tag:KkQfh6OymvCt4uC13p318g==,type:str]
sops:
    kms: []
    gcp_kms: []
    azure_kv: []
    hc_vault: []
    lastmodified: '2021-10-21T10:56:37Z'
    mac: ENC[AES256_GCM,data:Tl1V1PuI5tZ0Hu3qxxzpDNeKQkuW0g/x/Mlp1yM6HaBqDr+r2FukLdYSYqjjJ3A8g+YkpvMib50M7j0V7zoX9sgCvMKEg86pRsWtThv8n/L+bsjClVTqnhJ9nfYlaPOMlvggbiMOE5hXPIuVz8WXYoVYJ2cVNCd/GfwOraUmj7I=,iv:n7HVI13okfbW3FS/ZsJ2GNmibudxc/TlkLa3umQQ+vc=,tag:R4ikep1wlxlDWlODJqFHHw==,type:str]
    pgp:
    -   created_at: '2021-10-21T10:56:37Z'
        enc: |
            -----BEGIN PGP MESSAGE-----

            hQGMA3muqimBu2IIAQwAkhR19/6roLq06oaD12vqDMes3/8FweAHxa6TLKg+LRjp
            2/ntiRJHPBP9DYYFZbkTo8lAmIdVF7KfGIqWgPm5JiNhqfVRhyGPCRgBE7+I8qH6
            EML9Vo/76kJLHtIjs5rOg7OXgwwitaibs1q6uyVY8TuaGXYIOO1iwL9xVtbayIry
            NMQd1tFcNb6Vb86Plqm+T1VnSOJMUvryxrLelx89UNM0ctepyVu6YY9jpBjV0QLJ
            NqNkKAGIMv3RNa9bZHTwveo9T0oXtFnk5H33BxH0ky/DGpD+5Ch1YgbzbqVnr+Bm
            RX0R/GRhS9IDInd+eiyVX6y3LR5di0fc8TuK43+96wTG+2+ck+lbMrkHYsL2UJNv
            bAjlOWmIcL4UwGlEOj4EzwcEx+xP3dq57pJ+DasfNwVqps2Kk+ofodR7d6gx7ELH
            UQmLypCtkRic9v8fVSA2vEL8hAlg9bT8tpHLhHMOwe228cL5dTzFD60RoP+ovRar
            jIU59Pnu1bnM4pXWEVA20l4BzJ8Fd6gj3TfAg/7Mat+dnTaUwnPgRSybFn0ZZHMW
            RJDBPkMGFfSGRDfLeD37d61mI31360/w/61LaVp1sdDYodBJCRZFA1YzbqZcxnDl
            YRjRmpcVRnO+o72CnU/P
            =V4l4
            -----END PGP MESSAGE-----
        fp: 73019E949C1D3C3D1BE8B718C7CD51A565AB592C
    encrypted_suffix: Templates
    version: 3.6.1`, // https://github.com/luca-iachini/argocd-test/blob/af0c8eaba270bc918108c8bc3b909f26a4fe995d/kustomize/base/app1/secrets.enc.yaml#L4
		// The "data"-key is before the identifier "kind: Secret"
		"before-min-length.yaml": `apiVersion: v1
data:
	extra: YmFyCg==
kind: secret
metadata:
	name: secret-sa-sample
	annotations:
		kubernetes.io/service-account.name: 'sa-name'`,
		"before-template.yaml": `apiVersion: v1
 data:
 	password: {{ .Values.Password }}
 kind: secret
 metadata:
 	name: secret-sa-sample
 	annotations:
 		kubernetes.io/service-account.name: 'sa-name'`,
		"before-externalsecret1.yml": `apiVersion: 'kubernetes-client.io/v1'
metadata:
  name: actions-exporter
  namespace: github-actions-exporter
spec:
  backendType: secretsManager
  data:
    - key: MySecretManagerKey
      name: github_token
      property: github_token
kind: ExternalSecret
`,
		"before-externalsecret2.yml": `apiVersion: external-secrets.io/v1beta1
spec:
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secretsmanager
  refreshInterval: 1h
  target:
    creationPolicy: Owner
  data:
    - secretKey: api-key
      remoteRef:
        key: my-secrets-manager-secret
metadata:
  name: api-key
  namespace: my-namespace
kind: ExternalSecret
`,
		"before-sopssecret.yml": `apiVersion: isindir.github.com/v1alpha3
spec:
  secretTemplates:
    - name: my-secret-name-1
      labels:
        label1: value1
      annotations:
        key1: value1
      data:
        data-name1: ZGF0YS12YWx1ZTE=
        data-nameM: ZGF0YS12YWx1ZU0=
kind: SopsSecret
metadata:
  name: sopssecret-sample
`, // https://github.com/isindir/sops-secrets-operator/blob/8aaf8bb368dc841a2d57f251bd839f08216a9328/config/samples/isindir_v1alpha3_sopssecret.yaml#L4
		// The "data"-key is after the identifier "kind: Secret"
		"after-min-length.yaml": `apiVersion: v1
kind: secret
data:
	extra: YmFyCg==
metadata:
	name: secret-sa-sample
	annotations:
		kubernetes.io/service-account.name: 'sa-name'`,
		"after-externalsecret1.yml": `apiVersion: 'kubernetes-client.io/v1'
kind: ExternalSecret
metadata:
  name: actions-exporter
  namespace: github-actions-exporter
spec:
  backendType: secretsManager
  data:
    - key: MySecretManagerKey
      name: github_token
      property: github_token
    - key: MySecretManagerKey`,
		"after-externalsecret2.yml": `apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-key
  namespace: my-namespace
spec:
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secretsmanager
  refreshInterval: 1h
  target:
    creationPolicy: Owner
  data:
    - secretKey: api-key
      remoteRef:
        key: my-secrets-manager-secret`,
		"after-sopssecret.yml": `apiVersion: isindir.github.com/v1alpha3
kind: SopsSecret
metadata:
  name: sopssecret-sample
spec:
  secretTemplates:
    - name: my-secret-name-0
      labels:
        label0: value0
        labelK: valueK
      annotations:
        key0: value0
        keyN: valueN
      stringData:
        data-name0: data-value0
        data-nameL: data-valueL
    - name: my-secret-name-1
      labels:
        label1: value1
      annotations:
        key1: value1
      data:
        data-name1: ZGF0YS12YWx1ZTE=
        data-nameM: ZGF0YS12YWx1ZU0=`,
		"after-empty-data.yaml": `apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-csrf
  namespace: kubernetes-dashboard
type: Opaque
data:
  csrf: ""
`,
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
