#!/usr/bin/env bash
# Keep running after a failed check, but fail the job if any check fails.
set -euo pipefail
log_dir=$1
shift
mkdir -p "$log_dir"
status=0
for check in "$@"; do
  echo "::group::check $check"
  if nix eval --raw ".#checks.x86_64-linux.$check.drvPath" > "$log_dir/$check.drv" 2> "$log_dir/$check.eval.log" &&
    nix build -L --no-link --max-jobs 1 --cores 2 ".#checks.x86_64-linux.$check" 2>&1 | tee "$log_dir/$check.log"; then
    printf '%s PASS\n' "$check" | tee -a "$log_dir/results.txt"
  else
    cat "$log_dir/$check.eval.log"
    printf '%s FAIL\n' "$check" | tee -a "$log_dir/results.txt"
    status=1
  fi
  echo '::endgroup::'
done
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  cat "$log_dir/results.txt" >> "$GITHUB_STEP_SUMMARY"
fi
exit "$status"
