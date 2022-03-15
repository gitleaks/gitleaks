package detect

// stopwords used for ignoring detected secrets if the secrets
// contains any of these stopwords. When checking the secret for
// stopwords, the secret will be normalized to lowercase characters.
var stopWords = []string{
	"process",
	"getenv",
	".env",
	"env(",
	"env.",
	"setting",
	"load",
	"token",
	"password",
	"secret",
	"api_key",
	"apikey",
	"api-key",
}
