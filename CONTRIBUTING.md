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
           // Human readable description of the rule
           Description: "Beamer API token",

           // Unique ID for the rule
           RuleID:      "beamer-api-token",

           // Regex capture group for the actual secret



           // Regex used for detecting secrets. See regex section below for more details
           Regex: GenerateSemiGenericRegex([]string{"beamer"}, `b_[a-z0-9=_\-]{44}`, true)

           // Keywords used for string matching on fragments (think of this as a prefilter)
           Keywords: []string{"beamer"},
       }

       // validate
       tps := []string{
           generateSampleSecret("beamer", "b_"+secrets.NewSecret(alphaNumericExtended("44"))),
       }
       fps := []string{
           `R21A-A-V010SP13RC181024R16900-CN-B_250K-Release-OTA-97B6C6C59241976086FABDC41472150C.bfu`,
       }
       return validate(r, tps, fps)
   }
   ```

   Feel free to use this example as a template when writing new rules.
   This file should be fairly self-explanatory except for a few items;
   regex and secret generation. To help with maintence, _most_ rules should
   be uniform. The functions,
   [`GenerateSemiGenericRegex`](https://github.com/zricethezav/gitleaks/blob/master/cmd/generate/config/rules/rule.go#L31) and [`GenerateUniqueTokenRegex`](https://github.com/zricethezav/gitleaks/blob/master/cmd/generate/config/rules/rule.go#L44) will generate rules
   that follow defined patterns.

   The function signatures look like this:

   ```golang
   func GenerateSemiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp

   func GenerateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp
   ```

   `GenerateSemiGenericRegex` accepts a list of identifiers, a regex, and a boolean indicating whether the pattern should be case-insensitive.
   The list of identifiers _should_ match the list of `Keywords` in the rule
   definition above. Both `identifiers` in the `GenerateSemiGenericRegex`
   function _and_ `Keywords` act as filters for Gitleaks telling the program
   "_at least one of these strings must be present to be considered a leak_"

   `GenerateUniqueTokenRegex` just accepts a regex and a boolean indicating whether the pattern should be case-insensitive. If you are writing a rule for a
   token that is unique enough not to require an identifier then you can use
   this function. For example, Pulumi's API Token has the prefix `pul-` which is
   unique enough to use `GenerateUniqueTokenRegex`. But something like Beamer's API
   token that has a `b_` prefix is not unique enough to use `GenerateUniqueTokenRegex`,
   so instead we use `GenerateSemiGenericRegex` and require a `beamer`
   identifier is part of the rule.
   If a token's prefix has more than `3` characters then you could
   probably get away with using `GenerateUniqueTokenRegex`.

   Last thing you'll want to hit before we move on from this file is the
   validation part. You can use `generateSampleSecret` to create a secret for the
   true positives (`tps` in the example above) used in `validate`.

1. Update `cmd/generate/config/main.go`. Extend `configRules` slice with
   the `rules.Beamer(),` in `main()`. Try and keep
   this alphabetically pretty please.

1. Run `make config/gitleaks.toml`

1. Check out your new rules in `config/gitleaks.toml` and see if everything looks good.

1. Open a PR
