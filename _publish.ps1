# One-shot local publish trigger: ship committed work and dispatch the NuGet publish CI.
#
#   1. Aborts if the working tree has any uncommitted changes — commit or stash first.
#   2. git pull (merge) — picks up earlier CI bump commits ("Publish vX.Y.Z" by github-actions[bot]).
#   3. git push — CI publishes what is on GitHub, not what is on this machine.
#   4. Dispatches publish_nugets.yml, which does the real work on GitHub via the shared module in
#      vpnhood/VpnHood (adopt/bump the version, pack, push to nuget.org) and pushes the version-bump
#      commit BACK to this branch — so pull again before your next work.
#
# Requires the GitHub CLI (gh) authenticated for this repo.
#
# Usage:
#   ./_publish.ps1                # publish what is already committed
#   ./_publish.ps1 -prerelease    # manual escape hatch: X.Y.Z-prerelease

param(
	# Forwarded to CI: publish X.Y.Z-prerelease instead of the stable version (manual-only).
	[switch]$prerelease
);

$ErrorActionPreference = "Stop";
Push-Location $PSScriptRoot;
try {
	$branch = git branch --show-current;
	if ([string]::IsNullOrWhiteSpace($branch)) { throw "_publish: detached HEAD; check out a branch first."; }

	# Refuse a dirty tree: CI publishes what is committed, and git pull below needs a clean tree anyway.
	$dirty = git status --porcelain;
	if ($dirty) { throw "_publish: working tree has uncommitted changes; commit or stash them first.`n$($dirty -join "`n")"; }

	# Merge in remote work (typically the last publish's bump commit) so the push below fast-forwards.
	git pull origin $branch --no-rebase;
	if ($LASTEXITCODE -ne 0) { throw "_publish: git pull failed (exit $LASTEXITCODE) — resolve and retry."; }

	git push origin $branch;
	if ($LASTEXITCODE -ne 0) { throw "_publish: git push failed (exit $LASTEXITCODE)"; }

	# Dispatch the CI (repo inferred from the git remote of the current directory).
	$prereleaseParam = if ($prerelease) { "true" } else { "false" };
	gh workflow run publish_nugets.yml --ref $branch -f prerelease=$prereleaseParam;
	if ($LASTEXITCODE -ne 0) { throw "_publish: gh workflow run failed (exit $LASTEXITCODE)"; }

	Write-Host "Publish dispatched on '$branch' (prerelease=$prereleaseParam). CI bumps the version, publishes the NuGets, and pushes the bump commit back — 'git pull' before your next work." -ForegroundColor Green;
	Start-Sleep -Seconds 3;
	gh run list --workflow publish_nugets.yml --branch $branch --limit 1;
}
finally {
	Pop-Location;
}
