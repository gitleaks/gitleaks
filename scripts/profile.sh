#! /usr/bin/env bash
# NAME
#     profile.sh - generate gitleaks profile data
#
# USAGE
#     profile.sh <gitleaks-path> <benchmark-repo-path>
#
# DESCRIPTION
#     Generates profile data for tuning gitleaks performance under ./profile/<timestamp>
#
#			Options:
#     	<gitleaks-path>       - gitleaks binary to profile
#     	<benchmark-repo-path> - git repo to run profile against
#
# SEE ALSO
#     Dave Cheney GopherCon 2019 talk on go profiling:
#
#     https://www.youtube.com/watch?v=nok0aYiGiYA
#
set -euo pipefail
gitleaks_path="$1"
test_repo_path="$2"
base_scan_cmd="${gitleaks_path} --exit-code=0 --max-decode-depth 8"
base_profile_dir="profile/$(date +%s)"

log() {
	echo >&2 "$@"
}

log '========================================================================'
log 'generating profile data'
log '------------------------------------------------------------------------'
# Warm up the fs and also get benchmark data
for scan_mode in dir git
do
	profile_dir="${base_profile_dir}/${scan_mode}"
	scan_cmd="${base_scan_cmd} ${scan_mode} ${test_repo_path}"
	mkdir -p "${profile_dir}"

	echo "- mode: ${scan_mode}"
	# include hyperfine benchmrak results if hyperfine is installed
	if command -v hyperfine > /dev/null
	then
		export_path="${profile_dir}/benchmark.json"
		echo "  benchmark:"
		echo "    tool: hyperfine"
		hyperfine -w 3 --export-json "${export_path}" "${scan_cmd}" &> /dev/null
		echo "    path: ${export_path}"
		# Show the results if we can :D
		if command -v yq > /dev/null
		then
			 echo "    results:"
			 yq -P -oy \
				 '.results[] | pick(["mean","stddev","median","user","system","min","max"])' \
				  ${export_path} | sed 's/^/      /g'
		else
			echo "    view: ${PAGER:-less} ${export_path}"
		fi
	fi

	# generate profile data
	echo "  profile:"
	for profile_mode in cpu mem trace
	do
		# Generate diagnostics data
		${scan_cmd} --diagnostics=$profile_mode --diagnostics-dir="${profile_dir}" &> /dev/null
		profile_file="$(find "${profile_dir}" -type f -name "${profile_mode}*")"
		echo "    - mode: ${profile_mode}"
		echo "      path: ${profile_file}"
		if [[ "${profile_mode}" = "trace" ]]
		then
			echo "      view: go tool trace ${profile_file}"
		else
			echo "      view: go tool pprof -http=localhost: ${gitleaks_path} ${profile_file}"
		fi
	done
done
log '------------------------------------------------------------------------'
log "results in: ${base_profile_dir}"
log '========================================================================'
