#!/usr/bin/env bash
#
# Build the Sentinel deploy package from what git tracks, plus nothing else.
#
#   source scripts/lib/build-package.sh
#   build_sentinel_package "$TARBALL" "$REPO_ROOT" || die "..."
#
# ---------------------------------------------------------------------------
# Why "git tracks it" is the boundary, and not a --exclude list
#
# `credentiale.txt` (2352 B) and `env.txt` (129 B) sat at the repo root,
# matched by .gitignore (`credentiale*.txt`, `*env*.txt`), never `git add`ed —
# and still ended up inside the tarball this file replaces, world-readable in
# /tmp on a host, because the old packaging was `tar -C "$REPO_ROOT" .` minus a
# hand-maintained denylist that had never heard of either name. A denylist has
# to be told about every secret file that will ever exist, by name, before it
# is created. `git ls-files` already knows, the moment the file is created,
# because .gitignore told IT once — the same file that made both names
# unfamiliar to `git add -A` in the first place.
#
# This does not need a matching allowlist of untracked-but-needed paths: the
# one candidate — the vendored dashboard assets under
# sentinel/web/static/vendor/, gitignored on purpose because a minified blob in
# git is unreviewable — is fetched by scripts/vendor-assets.sh, which
# deploy/install.sh's step 25-adjacent hook runs ON THE HOST after extraction,
# not shipped in the package. Checked 2026-09-08: nothing else in the tree that
# install.sh reads is both gitignored and required.
#
# "git tracks it" only answers half the question, though — it says nothing
# about a file that is neither tracked NOR gitignored, because it is simply
# NEW and nobody has `git add`ed it yet. `sentinel/telegram/callback_sign.py`
# was exactly that on 8 Sep 2026: new, untracked, imported by the SAME commit's
# modified `bot.py` — which WAS tracked, so it shipped. The result was a green
# build, a green test suite (nothing in the working tree was missing FROM the
# checkout, only from git's index), and a host crash-looping on import the
# moment the tarball landed. `build_sentinel_package` below therefore also
# runs `git ls-files --others --exclude-standard` over the same categories and
# REFUSES to build at all if that turns up anything — an untracked file is not
# quietly left out the way a gitignored one correctly is; it is a package this
# function will not build until someone `git add`s the file or deletes it.
#
# Content still comes from the WORKING TREE, not from git's object store —
# this is `git ls-files` picking which paths travel, then `tar` reading each
# one off disk, not `git archive HEAD`. An uncommitted fix in a tracked file
# still ships, matching what every deploy before this one did.
#
# The pathspecs below trim CATEGORIES that ARE tracked but do not belong on
# the wire — reasons unchanged from the --exclude list this replaces:
#
#   secrets/    — only secrets/.gitkeep is tracked; secrets travel over stdin,
#                 never inside a tarball that lands in /tmp on the server.
#   tests/,docs/— reviewer- and operator-facing; nothing install.sh runs reads
#                 them.
#   watcher/    — the external witness. Its whole value is running somewhere
#                 the monitored host cannot reach; shipping a copy here would
#                 put the thing that reports Sentinel's death on the machine
#                 whose death it reports.
#   aggregator/ — the archive of what left this machine. A copy of its schema
#                 and credentials-handling code on the archived host defeats
#                 "what left cannot be deleted from here".
#   scratchpad/, .claude/worktrees/ — neither is ever tracked today (see
#                 .gitignore), excluded here too so a future `git add -f`
#                 still cannot ship a falsification harness or a second
#                 checkout of the repository.
#
# Deliberately does not `set` any shell option here: this file is `source`d
# into deploy.sh (set -euo pipefail) and wizard.sh (set -uo pipefail), and a
# `set` in a sourced file changes the CALLER's options for the rest of its
# run — sourcing this must not silently turn a caller's `-e` off.

# The categories git DOES track but that must not reach the wire — see the
# header comment above for why each one. ONE array, used for both the list of
# what ships and the untracked-file check below: two separate copies of this
# same list is exactly the shape of drift that let credentiale.txt slip past
# the old --exclude list in the first place.
_SENTINEL_PACKAGE_PATHSPECS=(
    .
    ':!secrets'
    ':!tests'
    ':!docs'
    ':!watcher'
    ':!aggregator'
    ':!scratchpad'
    ':!.claude/worktrees'
)

# build_sentinel_package OUT_TARBALL REPO_ROOT
#
# Writes a gzipped tar of REPO_ROOT's git-tracked files (see above for which
# categories are trimmed) to OUT_TARBALL.
#
# Also refuses to build at all if anything UNTRACKED and NOT gitignored sits
# under a shipped category — `sentinel/telegram/callback_sign.py`, 8 Sep 2026:
# new, untracked, imported by the modified `bot.py`, which WAS tracked and
# DID ship. The result is a green deploy and a host crash-looping on import,
# because "tracked" answers "is this shipped", not "does this exist" — a file
# on disk that git does not know about yet is invisible to `git ls-files`
# either way, tracked-list or --exclude list, and this is the one guard that
# looks at "exists but not yet told to git" as its own failure mode instead of
# assuming everything real gets caught by one of the other two checks.
#
# Exit codes:
#   0  package built at OUT_TARBALL
#   2  could not even determine what belongs in the package — no git on PATH,
#      REPO_ROOT is not a git working tree, or git returned an empty list.
#      Never falls back to "ship everything" (that is the bug this replaces)
#      or "ship nothing" silently; the caller is expected to die on nonzero.
#   3  untracked, non-ignored files exist under a shipped category — named on
#      stderr. This is a correctness gate, not a confirmation prompt: nothing
#      the caller passes (deploy.sh's --yes included) skips it, because
#      answering "yes" to a question this function never asks is not consent
#      to ship a file nobody has reviewed.
#   *  whatever `tar` returned
build_sentinel_package() {
    local out_tarball="$1" repo_root="$2"

    if ! command -v git >/dev/null 2>&1; then
        echo "build_sentinel_package: git is not on PATH — cannot tell tracked from ignored, refusing to guess" >&2
        return 2
    fi
    if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "build_sentinel_package: ${repo_root} is not a git working tree — this packaging depends on git to keep gitignored files out and cannot fall back to \"ship everything\" without reintroducing that hole. Deploy from a git clone (see docs/DEPLOYMENT.md §3.1)." >&2
        return 2
    fi

    local list untracked
    list="$(mktemp)" || { echo "build_sentinel_package: could not create a temporary file" >&2; return 2; }
    untracked="$(mktemp)" || {
        echo "build_sentinel_package: could not create a temporary file" >&2
        rm -f "$list"; return 2
    }
    # No RETURN trap: that stays armed after this function returns, in the
    # CALLER's shell (this file is `source`d, never executed as its own
    # process) — a later `source` of anything else in that shell would then
    # hit this trap on ITS return too. Every exit path below cleans up by
    # hand instead.

    git -C "$repo_root" ls-files -z -- "${_SENTINEL_PACKAGE_PATHSPECS[@]}" \
        > "$list" || {
        echo "build_sentinel_package: git ls-files failed" >&2
        rm -f "$list" "$untracked"; return 2
    }

    # An empty list would satisfy every "nothing forbidden is in the package"
    # test perfectly, and it is not a package.
    if [[ ! -s "$list" ]]; then
        echo "build_sentinel_package: git ls-files returned nothing for ${repo_root} — an empty package is not a safe default, refusing" >&2
        rm -f "$list" "$untracked"; return 2
    fi

    git -C "$repo_root" ls-files -z --others --exclude-standard -- \
        "${_SENTINEL_PACKAGE_PATHSPECS[@]}" > "$untracked" || {
        echo "build_sentinel_package: git ls-files --others failed" >&2
        rm -f "$list" "$untracked"; return 2
    }
    if [[ -s "$untracked" ]]; then
        echo "build_sentinel_package: untracked, non-ignored files sit under what this package would ship. A file git has never been told about ships nowhere — not in this tarball, not in the old --exclude one either — while code already tracked can import it, pass locally, and crash-loop the moment it lands on the host. adaugă în git sau șterge:" >&2
        tr '\0' '\n' < "$untracked" | sed 's/^/    /' >&2
        rm -f "$list" "$untracked"
        return 3
    fi
    rm -f "$untracked"

    # `|| rc=$?`, not a bare command followed by `local rc=$?`: this file is
    # `source`d into callers running under `set -e` (deploy.sh), and a failing
    # `tar` as a standalone statement would abort right there, before the
    # cleanup below ever ran, leaking $list back into the earlier bug this
    # function exists to not have. `cmd || rc=$?` is the one shape `set -e`
    # exempts (the failing command is not the last in its `||` list), so this
    # runs even when tar does not.
    local rc=0
    tar -C "$repo_root" --null -T "$list" -czf "$out_tarball" || rc=$?
    rm -f "$list"
    return $rc
}
