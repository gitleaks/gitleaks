# Contribution guidelines

## General

### Issues

If you have a feature or bug fix you would like to contribute please check if
there are any open issues describing your proposed addition. If there are open
issues, make a comment stating you are working on fixing or implementing said
issue. If not, then please open an issue describing your addition. Make sure to
link your PR to an issue.

### Pull Requests

Fill out the template as best you can. Make sure your tests pass. If you see a
PR that isn't one you opened and want it introduced in the next release,
give it a :thumbsup: on the PR description.

## Adding new Gitleaks rules

If you want to add a new rule to the [default Gitleaks configuration](https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml) then follow these steps.

1. Create a `cmd/generate/config/rules/{provider}.go` file.
   This file is used to generate a new Gitleaks rule.
   Let's look at `beamer.go` for example. Comments have been added for context.

   ```golang
   func Beamer() *config.Rule {
       // Define Rule
       r := config.Rule{
           // Human redable description of the rule
           Description: "Beamer API token",

           // Unique ID for the rule
           RuleID:      "beamer-api-token",

           // Regex capture group for the actual secret
           SecretGroup: 1,


           // Regex used for detecting secrets. See regex section below for more details
           Regex: generateSemiGenericRegex([]string{"beamer"}, `b_[a-z0-9=_\-]{44}`),

           // Keywords used for string matching on fragments (think of this as a prefilter)
           Keywords: []string{"beamer"},
       }

       // validate
       tps := []string{
           generateSampleSecret("beamer", "b_"+secrets.NewSecret(alphaNumericExtended("44"))),
       }
       return validate(r, tps, nil)
   }
   ```

   Feel free to use this example as a template when writing new rules.
   This file should be fairly self-explanatory except for a few items;
   regex and secret generation. To help with maintence, _most_ rules should
   be uniform. The functions,
   [`generateSemiGenericRegex`](https://github.com/zricethezav/gitleaks/blob/master/cmd/generate/config/rules/rule.go#L31) and [`generateUniqueTokenRegex`](https://github.com/zricethezav/gitleaks/blob/master/cmd/generate/config/rules/rule.go#L44) will generate rules
   that follow defined patterns.

   The function signatures look like this:

   ```golang
   func generateSemiGenericRegex(identifiers []string, secretRegex string) *regexp.Regexp

   func generateUniqueTokenRegex(secretRegex string) *regexp.Regexp
   ```

   `generateSemiGenericRegex` accepts a list of identifiers and a regex.
   The list of identifiers _should_ match the list of `Keywords` in the rule
   definition above. Both `identifiers` in the `generateSemiGenericRegex`
   function _and_ `Keywords` act as filters for Gitleaks telling the program
   "_at least one of these strings must be present to be considered a leak_"

   `generateUniqueToken` just accepts a regex. If you are writing a rule for a
   token that is unique enough not to require an identifier then you can use
   this function. For example, Pulumi's API Token has the prefix `pul-` which is
   unique enough to use `generateUniqueToken`. But something like Beamer's API
   token that has a `b_` prefix is not unqiue enough to use `generateUniqueToken`,
   so instead we use `generateSemiGenericRegex` and require a `beamer`
   identifier is part of the rule.
   If a token's prefix has more than `3` characters then you could
   probably get away with using `generateUniqueToken`.

   Last thing you'll want to hit before we move on from this file is the
   validation part. You can use `generateSampleSecret` to create a secret for the
   true positives (`tps` in the example above) used in `validate`.

1. Update `cmd/generate/config/main.go`. Add a line like
   `configRules = append(configRules, rules.Beamer())` in `main()`. Try and keep
   this alphabetically pretty please.

1. Change directories into `cmd/generate/config` and run `go run main.go`

   ```
   cd cmd/generate/config && go run main.go
   ```

1. Check out your new rules in `config/gitleaks.toml` and see if everything looks good.

1. Open a PR
