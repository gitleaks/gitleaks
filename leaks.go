package main

// TODO https://medium.com/@sebdah/go-best-practices-error-handling-2d15e1f0c5ee
// implement better error handling

// Commit is so and so

/*
// start kicks off the audit
func start(repos []Repo, owner *Owner, opts *Options) error {
	var (
		report []Leak
		err error
	)
	defer rmTmpDirs(owner, opts)

	// interrupt handling
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		rmTmpDirs(owner, opts)
		os.Exit(1)
	}()

	// run checks on repos
	for _, repo := range repos {
		dotGitPath := filepath.Join(repo.path, ".git")
		if _, err := os.Stat(dotGitPath); err == nil {
			if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
				log.Fatal(err)
			}
			// use pre-cloned repo
			fmt.Printf("Checking \x1b[37;1m%s\x1b[0m...\n", repo.url)
			err = exec.Command("git", "fetch").Run()
		} else {
			// no repo present, clone it
			if err := os.Chdir(fmt.Sprintf(owner.path)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Cloning \x1b[37;1m%s\x1b[0m...\n", repo.url)
			err = exec.Command("git", "clone", repo.url).Run()
		}
		if err != nil {
			log.Printf("failed to fetch repo %v", err)
			return nil
		}

		report, err = audit(&repo, opts)
		if err != nil {
			return nil
		}

		if len(report) == 0 {
			fmt.Printf("No Leaks detected for \x1b[35;2m%s\x1b[0m...\n", repo.url)
		}

		if opts.EnableJSON && len(report) != 0 {
			writeReport(report, repo)
		}
	}
	return nil
}
*/

// Used by start, writeReport will generate a report and write it out to
// $GITLEAKS_HOME/report/<owner>/<repo>. No report will be generated if
// no leaks have been found

