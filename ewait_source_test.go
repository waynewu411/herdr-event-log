package main

// TestCheckSource_*/TestSync_* exercise the vendoring commands added to
// scripts/herdr-ewait.sh by issue #13 (hardened through adversarial
// review): --check-source [--latest] and --sync <sha|main>. Unlike
// ewait_test.go/ewait_resolution_test.go, these never start the fake herdr
// stub (both commands are herdr-free by design) and instead run against a
// throwaway COPY of the script, since --sync rewrites the script file in
// place. Network access is replaced by two test-only env overrides the
// script itself documents: HERDR_EWAIT_RAW_BASE_URL (raw content fetch) and
// HERDR_EWAIT_REMOTE_BASE_URL (the remote used for ls-remote/fetch), both
// gated behind HERDR_EWAIT_TEST_HOOKS=1 and both pointing at local fixtures
// (a plain directory tree served via file://, and a local bare git repo) so
// no test ever touches the network. Every script invocation runs under a
// hermetic, scrubbed environment (see hermeticEnv) so a stray GIT_*/
// HERDR_EWAIT_* variable in the developer's shell can't change a result.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

var sha256HexPattern = regexp.MustCompile(`[0-9a-f]{64}`)

const (
	exitCheckSourceDrift          = 7
	exitCheckSourceFail           = 8
	exitCheckSourceUpstreamNewer  = 9
	exitSyncNoSidecar             = 10
	exitSyncOnDefaultBranch       = 11
	exitSyncBadDownload           = 12
	exitCheckSourceExpectVendored = 13
	exitSyncPartiallyApplied      = 14
)

const fakeRepo = "example-owner/example-repo"
const fakeScriptRelPath = "scripts/herdr-ewait.sh"

// --- fixture helpers ---

func realScriptBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(ewaitScriptPath(t))
	if err != nil {
		t.Fatalf("read real script: %v", err)
	}
	return data
}

// copyScriptToDir copies the real scripts/herdr-ewait.sh into destDir so a
// test can let --sync mutate it without touching the repo's own copy.
func copyScriptToDir(t *testing.T, destDir string) string {
	t.Helper()
	dest := filepath.Join(destDir, "herdr-ewait.sh")
	if err := os.WriteFile(dest, realScriptBytes(t), 0o755); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
	return dest
}

// fakeUpstreamScript returns syntactically-valid, self-describing
// herdr-ewait.sh-shaped content (so it passes --sync's content checks:
// non-empty, correct shebang, the SIDECAR_NAME sentinel, and the trailing
// end-of-file sentinel) but distinguishable from the real file via a
// trailing marker comment, so a hash comparison correctly reports a
// difference.
func fakeUpstreamScript(t *testing.T, marker string) []byte {
	t.Helper()
	base := realScriptBytes(t)
	return append(append([]byte{}, base...), []byte("\n# test marker: "+marker+"\n")...)
}

func writeSidecar(t *testing.T, dir, repo, path, sha string) string {
	t.Helper()
	content := "# test sidecar\nrepo=" + repo + "\npath=" + path + "\nsha=" + sha + "\n"
	p := filepath.Join(dir, "herdr-ewait.source")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	return p
}

// writeRawFixture lays out <baseDir>/<repo>/<sha>/<path> = content, the
// shape HERDR_EWAIT_RAW_BASE_URL expects (mirroring
// https://raw.githubusercontent.com/<repo>/<sha>/<path>).
func writeRawFixture(t *testing.T, baseDir, repo, sha, path string, content []byte) {
	t.Helper()
	full := filepath.Join(baseDir, filepath.FromSlash(repo), sha, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func rawBaseURL(dir string) string { return "file://" + dir }

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=ewait-test", "GIT_AUTHOR_EMAIL=ewait-test@example.com",
		"GIT_COMMITTER_NAME=ewait-test", "GIT_COMMITTER_EMAIL=ewait-test@example.com",
		"GIT_CONFIG_NOSYSTEM=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// setupFakeRemote builds a local bare git repo at <remoteBase>/<repo> with
// two commits on its default branch ("main"), for HERDR_EWAIT_REMOTE_BASE_URL
// to point at. Returns the remote base dir plus the first and second (HEAD)
// commit shas — both are real, reachable commits, satisfying the ancestry
// check (verify_sha_on_upstream) without any extra setup.
func setupFakeRemote(t *testing.T, repo string) (remoteBase, firstSHA, secondSHA string) {
	t.Helper()
	work := t.TempDir()
	gitCmd(t, work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "placeholder.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "add", "placeholder.txt")
	gitCmd(t, work, "commit", "-q", "-m", "v1")
	firstSHA = strings.TrimSpace(gitCmd(t, work, "rev-parse", "HEAD"))

	remoteBase = t.TempDir()
	bareDir := filepath.Join(remoteBase, filepath.FromSlash(repo))
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, remoteBase, "clone", "-q", "--bare", work, bareDir)

	if err := os.WriteFile(filepath.Join(work, "placeholder.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "add", "placeholder.txt")
	gitCmd(t, work, "commit", "-q", "-m", "v2")
	secondSHA = strings.TrimSpace(gitCmd(t, work, "rev-parse", "HEAD"))
	gitCmd(t, work, "push", "-q", bareDir, "main")

	return remoteBase, firstSHA, secondSHA
}

// initGitRepoWithDefaultBranch makes dir a git work tree on "main" with one
// commit, and records refs/remotes/origin/HEAD as a REAL remote-tracking ref
// would be (pointing at refs/remotes/origin/main, itself a real ref —
// exactly what `git clone`/`git remote set-head origin -a` leaves behind),
// not directly at refs/heads/main. This distinction matters for the --short
// ambiguity tests: shortening refs/remotes/origin/HEAD when it points
// directly at refs/heads/main is unaffected by a same-named local branch
// (there's no "remotes/origin/" path component to begin with), so a
// same-named branch can only reproduce that specific ambiguity against a
// genuine remote-tracking ref.
func initGitRepoWithDefaultBranch(t *testing.T, dir string) {
	t.Helper()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init", "--allow-empty")
	headSHA := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	gitCmd(t, dir, "update-ref", "refs/remotes/origin/main", headSHA)
	gitCmd(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
}

// dropLocalOriginHeadRef removes the locally-recorded refs/remotes/origin/HEAD
// (and the refs/remotes/origin/main it points at) that initGitRepoWithDefaultBranch
// set up, forcing default_branch_of to fall through to its second resolution
// path — a read-only `git ls-remote --symref origin HEAD` against a real
// configured 'origin' remote — exactly as it would on a fresh work tree that
// never ran `git remote set-head origin -a`.
func dropLocalOriginHeadRef(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, ".git", "refs", "remotes", "origin", "HEAD")); err != nil {
		t.Fatalf("remove refs/remotes/origin/HEAD: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, ".git", "refs", "remotes", "origin", "main")); err != nil {
		t.Fatalf("remove refs/remotes/origin/main: %v", err)
	}
}

// setupLocalBareOrigin creates a local bare git repo (one commit on "main",
// HEAD pointing there) and returns its filesystem path — a fully offline
// stand-in for a real 'origin' remote, suitable for `git remote add origin
// <path>`, used to exercise default_branch_of's `ls-remote --symref origin
// HEAD` fallback without any network access.
func setupLocalBareOrigin(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	gitCmd(t, work, "init", "-q", "-b", "main")
	gitCmd(t, work, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init", "--allow-empty")
	bareParent := t.TempDir()
	bareDir := filepath.Join(bareParent, "origin.git")
	gitCmd(t, bareParent, "clone", "-q", "--bare", work, bareDir)
	return bareDir
}

// filesystemIsCaseSensitive reports whether t.TempDir()'s filesystem treats
// "case-probe" and "CASE-PROBE" as distinct directory entries. On a
// case-insensitive filesystem (e.g. macOS's default APFS), writing the
// second overwrites the first, so reading the first back afterward returns
// the second write's content instead of its own.
func filesystemIsCaseSensitive(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	lower := filepath.Join(dir, "case-probe")
	upper := filepath.Join(dir, "CASE-PROBE")
	if err := os.WriteFile(lower, []byte("lower"), 0o644); err != nil {
		t.Fatalf("case-sensitivity probe: write lower: %v", err)
	}
	if err := os.WriteFile(upper, []byte("upper"), 0o644); err != nil {
		t.Fatalf("case-sensitivity probe: write upper: %v", err)
	}
	got, err := os.ReadFile(lower)
	if err != nil {
		t.Fatalf("case-sensitivity probe: read lower back: %v", err)
	}
	return string(got) == "lower"
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeFakeGit/writeFakeCurl install a fully-fabricated git/curl on stubDir:
// they log their arguments to logPath and exit 0 (git) / 1 (curl) — used
// only to prove WHICH base URL a call targeted (the test-hook gate)
// without ever performing a real git/network operation.
func writeFakeGit(t *testing.T, stubDir, logPath string) {
	t.Helper()
	writeExec(t, filepath.Join(stubDir, "git"), "#!/usr/bin/env bash\nprintf 'git %s\\n' \"$*\" >> '"+logPath+"'\nexit 0\n")
}
func writeFakeCurl(t *testing.T, stubDir, logPath string) {
	t.Helper()
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\nprintf 'curl %s\\n' \"$*\" >> '"+logPath+"'\nexit 1\n")
}

// writeFakeHashTool installs a `sha256sum` on stubDir that always prints
// nothing and exits 0 — simulates a present-but-broken hash tool, for the
// empty-hash-output fail-closed guard.
func writeFakeEmptyHashTool(t *testing.T, stubDir string) {
	t.Helper()
	writeExec(t, filepath.Join(stubDir, "sha256sum"), "#!/usr/bin/env bash\nexit 0\n")
}

// hermeticEnv builds a minimal, explicit environment for a script invocation
// — PATH/HOME plus whatever the test passes — instead of inheriting the
// developer's full ambient environment (which could carry a stray GIT_DIR,
// GIT_WORK_TREE, or leftover HERDR_EWAIT_* variable that would silently
// change a result). TMPDIR is always a fresh t.TempDir(), never inside any
// git repo, so verify_sha_on_upstream's scratch dir and the script's own
// temp files never accidentally land inside a work tree.
// networkGuardDir returns a directory containing `git` and `curl` wrapper
// scripts that refuse (exit non-zero) any invocation whose arguments mention
// a real upstream host (https://, github.com, or githubusercontent.com),
// then exec the REAL binary otherwise (so a test that genuinely needs git —
// e.g. a local-repo ancestry check — still works). hermeticEnv puts this
// directory FIRST on PATH as defense-in-depth: even if the test-hook gate
// (HERDR_EWAIT_TEST_HOOKS=1 + HERDR_EWAIT_*_BASE_URL) ever regressed and let
// a call fall through to the real https://github.com/
// https://raw.githubusercontent.com bases, this stops a test from actually
// reaching the network — independent of git_safe's own GIT_* env scrub,
// which this backstops rather than replaces. A test that installs its own
// fake git/curl still wins (its stub dir is prepended in front of whatever
// hermeticEnv/testHookEnv returned).
func networkGuardDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"git", "curl"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		script := "#!/usr/bin/env bash\n" +
			"for a in \"$@\"; do\n" +
			"  case \"$a\" in\n" +
			"    *https://*|*github.com*|*githubusercontent.com*)\n" +
			"      echo \"network-guard: refused a real-host argument: $a\" >&2\n" +
			"      exit 17\n" +
			"      ;;\n" +
			"  esac\n" +
			"done\n" +
			"exec '" + real + "' \"$@\"\n"
		writeExec(t, filepath.Join(dir, tool), script)
	}
	return dir
}

// TestNetworkGuardDir_RefusesRealHostArguments verifies the guard itself
// : both wrapper scripts must refuse an argument naming a
// real upstream host, and must still pass through a harmless, local-only
// invocation (so it doesn't accidentally break every other test that relies
// on hermeticEnv for a genuine local git/curl operation).
func TestNetworkGuardDir_RefusesRealHostArguments(t *testing.T) {
	dir := networkGuardDir(t)

	for _, tc := range []struct {
		tool string
		args []string
	}{
		{"git", []string{"ls-remote", "https://github.com/owner/repo", "HEAD"}},
		{"git", []string{"fetch", "https://raw.githubusercontent.com/owner/repo/sha/path"}},
		{"curl", []string{"-fsSL", "https://raw.githubusercontent.com/owner/repo/sha/path"}},
	} {
		cmd := exec.Command(filepath.Join(dir, tc.tool), tc.args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s %v: want refusal (non-zero exit), got success; output=%q", tc.tool, tc.args, out)
		}
	}

	// A harmless, local-only git invocation must still work (passthrough to
	// the real binary) — the guard must not break genuine local git usage.
	cmd := exec.Command(filepath.Join(dir, "git"), "--version")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("git --version: want passthrough success, got error %v; output=%q", err, out)
	}
}

func hermeticEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	env := []string{
		"PATH=" + networkGuardDir(t) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
		// GIT_CONFIG_NOSYSTEM/GIT_CONFIG_GLOBAL here are inert for any call that
		// goes through the script's own git_safe: git_safe unsets EVERY ambient
		// GIT_* var (including whatever this env sets) before re-setting its own
		// specific list, which does not include GIT_CONFIG_GLOBAL — so these
		// never actually reach git that way. HOME is the only real lever (git
		// falls back to reading $HOME/.gitconfig once GIT_CONFIG_GLOBAL is
		// unset), hence a fresh temp dir below rather than passing through the
		// developer's real one.
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HOME=" + t.TempDir(),
	}
	return append(env, extra...)
}

func testHookEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return hermeticEnv(t, append([]string{"HERDR_EWAIT_TEST_HOOKS=1"}, extra...)...)
}

// deadHookEnv is hermeticEnv with the test-hook env vars pointed at an inert,
// nonexistent local file:// path — defense-in-depth for refusal-path tests
// that should never reach any network call in the first place: today they pass
// by refusing BEFORE either hook is consulted, but if a regression ever let one
// fall through past its guard, it would hit a dead local path instead of the
// real github.com/raw.githubusercontent.com.
func deadHookEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	dead := filepath.Join(t.TempDir(), "unreachable")
	return testHookEnv(t, append([]string{
		"HERDR_EWAIT_RAW_BASE_URL=file://" + dead,
		"HERDR_EWAIT_REMOTE_BASE_URL=file://" + dead,
	}, extra...)...)
}

// hermeticEnvCustomPath is hermeticEnv but with an explicit PATH (e.g. one built by
// minimalToolsPath, which deliberately excludes a tool like git).
// pathWithoutGit builds a PATH from symlinks to the SPECIFIC binaries the script
// needs (not whole directories, unlike minimalToolsPath): on a typical system git
// lives in the same directory as sed/tail/awk/mktemp/etc (e.g. /usr/bin), so a
// directory-based PATH would include git right back. Symlinking just the binaries
// themselves into one scratch dir guarantees git is absent from the resulting PATH.
func pathWithoutGit(t *testing.T) string {
	t.Helper()
	tools := []string{
		"bash", "grep", "sed", "tail", "wc", "cat", "date", "head", "tr", "sleep",
		"cut", "awk", "mv", "chmod", "mktemp", "diff", "dirname", "basename", "env", "curl",
	}
	dir := t.TempDir()
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
			t.Fatalf("symlink %s: %v", tool, err)
		}
	}
	check := exec.Command("env", "-i", "PATH="+dir, "sh", "-c", "command -v git")
	if err := check.Run(); err == nil {
		t.Skip("a real git binary is reachable even from the curated tool-only PATH; skipping")
	}
	return dir
}

// pathWithoutSha256sum builds a PATH with everything the script needs EXCEPT
// sha256sum, so resolve_hash_tool falls back to `shasum -a 256` — the hash
// tool actually observed (experimentally, on this dev machine) to escape a
// backslash-containing filename with a leading '\' when given one as an
// argument, unlike the sha256sum build that happens to be first on PATH here.
// Used by the sha256_of-via-stdin regression test so it reproduces the
// bug deterministically regardless of which hash tool a given CI machine
// happens to prefer.
func pathWithoutSha256sum(t *testing.T) string {
	t.Helper()
	tools := []string{
		"bash", "grep", "sed", "tail", "wc", "cat", "date", "head", "tr", "sleep",
		"cut", "awk", "mv", "rm", "chmod", "mktemp", "diff", "dirname", "basename",
		"env", "curl", "git", "shasum",
	}
	dir := t.TempDir()
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(dir, tool)); err != nil {
			t.Fatalf("symlink %s: %v", tool, err)
		}
	}
	// A direct file-exists check (not a nested `sh -c` probe — env's own PATH
	// search for the shell name itself is unreliable once PATH is pared down to
	// this curated dir, which doesn't contain "sh"): sha256sum must genuinely be
	// absent from dir and shasum must genuinely be present for this helper to
	// have done its job.
	if _, err := os.Stat(filepath.Join(dir, "sha256sum")); err == nil {
		t.Skip("a real sha256sum binary is reachable even from the curated tool-only PATH; skipping")
	}
	if _, err := os.Stat(filepath.Join(dir, "shasum")); err != nil {
		t.Skip("no shasum binary available on this machine; skipping")
	}
	return dir
}

func hermeticEnvCustomPath(t *testing.T, path string, extra ...string) []string {
	t.Helper()
	env := []string{"PATH=" + path, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if home := os.Getenv("HOME"); home != "" {
		env = append(env, "HOME="+home)
	}
	env = append(env, "TMPDIR="+t.TempDir())
	return append(env, extra...)
}

// withTempHome overrides env's HOME to a fresh t.TempDir() (adding it if
// absent). git_safe's own GIT_CONFIG_GLOBAL=/dev/null already blocks a real
// ~/.gitconfig from being read, but a test exercising a git-related code path
// should not depend on that scrub alone to avoid touching the developer's
// real home directory — belt and suspenders.
func withTempHome(t *testing.T, env []string) []string {
	t.Helper()
	home := t.TempDir()
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			out = append(out, "HOME="+home)
			replaced = true
		} else {
			out = append(out, kv)
		}
	}
	if !replaced {
		out = append(out, "HOME="+home)
	}
	return out
}

// envWithHomeGitConfig overrides env's HOME to a fresh temp dir containing a
// ~/.gitconfig with the given content, replacing any existing HOME= entry
// (same pattern as withTempHome). Used to simulate a real user gitconfig
// setting — e.g. [safe] bareRepository = explicit — that the script's own
// git_safe scrub does NOT neutralize (git_safe never sets GIT_CONFIG_GLOBAL
// itself, and unsets any the test tried to set via its own ambient-GIT_*
// scrub), so HOME/.gitconfig is the only way such a setting actually reaches
// git from a test.
func envWithHomeGitConfig(t *testing.T, env []string, gitconfig string) []string {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(gitconfig), 0o644); err != nil {
		t.Fatalf("write .gitconfig: %v", err)
	}
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			out = append(out, "HOME="+home)
			replaced = true
		} else {
			out = append(out, kv)
		}
	}
	if !replaced {
		out = append(out, "HOME="+home)
	}
	return out
}

// --- subprocess runner (no herdr stub: --check-source/--sync never call herdr) ---

func runEwaitScript(t *testing.T, scriptPath string, args []string, env []string, timeout time.Duration) ewaitResult {
	t.Helper()
	return startEwaitAt(t, scriptPath, args, env).wait(t, timeout)
}

// startEwaitAt runs scriptPath with EXACTLY env as its environment (no
// implicit os.Environ() merge) — callers that want ambient inheritance must
// build that explicitly (see the running-instance test below); every
// --check-source/--sync test uses hermeticEnv/testHookEnv instead.
func startEwaitAt(t *testing.T, scriptPath string, args []string, env []string) *ewaitProcess {
	t.Helper()
	requireEwaitTools(t)
	cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
	cmd.Env = env
	setNewProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start herdr-ewait.sh: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return &ewaitProcess{cmd: cmd, stdout: &stdout, stderr: &stderr, done: done}
}

// runRelative runs bash with scriptRelPath (relative to dir, bash's own cwd) and
// returns its result — for cases that must exercise bash resolving a RELATIVE $0
// itself (the CDPATH corruption guard only applies on that path; copyScriptToDir's
// usual absolute scriptPath bypasses it entirely).
func runRelative(t *testing.T, dir, scriptRelPath string, args []string, env []string, timeout time.Duration) ewaitResult {
	t.Helper()
	requireEwaitTools(t)
	cmd := exec.Command("bash", append([]string{scriptRelPath}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	setNewProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				t.Fatalf("run: %v", err)
			}
		}
		return ewaitResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
	case <-time.After(timeout):
		killProcessGroup(cmd)
		<-done
		t.Fatalf("timed out after %s (stdout: %q, stderr: %q)", timeout, stdout.String(), stderr.String())
		return ewaitResult{}
	}
}

// --- --check-source ---

func TestCheckSource_NoSidecar_IsSource(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "source") {
		t.Errorf("stdout should say this copy is the source; got %q", res.stdout)
	}
}

func TestCheckSource_SidecarIrregular_IsError(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	// A directory where the sidecar file should be: exists, but not a regular file.
	if err := os.Mkdir(filepath.Join(dir, "herdr-ewait.source"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (irregular sidecar must be an error, not 'no sidecar'); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	// Exit 8 is shared with several other refusals (invalid fields, fetch/ancestry
	// failure) — a directory in place of the sidecar would ALSO fail
	// validate_sidecar_fields once load_sidecar can't read it, landing on the same
	// exit code for the WRONG reason. Pin down the irregular-specific message.
	if !strings.Contains(res.stderr, "not a regular file") {
		t.Errorf("stderr should say the sidecar isn't a regular file specifically; got %q", res.stderr)
	}
	if strings.Contains(strings.ToLower(res.stdout), "is the source") {
		t.Errorf("must not report 'this copy is the source' for an irregular sidecar; got %q", res.stdout)
	}
}

// TestCheckSource_Refuse_SymlinkedSidecar/TestSync_Refuse_SymlinkedSidecar
// : a sidecar that is ITSELF a symlink — even one resolving
// to a genuine regular file — must be treated as irregular, the same as a
// directory or a dangling symlink. `[ -f "$p" ]` alone follows symlinks, so
// without an explicit `-L` check first, a symlinked sidecar pointing at a
// real file would read as "regular": read through a symlink this script
// doesn't control, and (for --sync) get REPLACED with a regular file
// carrying the link's own mode bits, silently changing what the sidecar path
// points to.
func TestCheckSource_Refuse_SymlinkedSidecar(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	realSidecarDir := t.TempDir()
	realSidecar := filepath.Join(realSidecarDir, "herdr-ewait.source")
	writeSidecar(t, realSidecarDir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	linkPath := filepath.Join(dir, "herdr-ewait.source")
	if err := os.Symlink(realSidecar, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (a symlinked sidecar must refuse, even one resolving to a regular file); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "not a regular file") {
		t.Errorf("stderr should say the sidecar isn't a regular file specifically; got %q", res.stderr)
	}
}

func TestSync_Refuse_SymlinkedSidecar(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	realSidecarDir := t.TempDir()
	realSidecar := filepath.Join(realSidecarDir, "herdr-ewait.source")
	writeSidecar(t, realSidecarDir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	linkPath := filepath.Join(dir, "herdr-ewait.source")
	if err := os.Symlink(realSidecar, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (a symlinked sidecar must refuse, even one resolving to a regular file); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "not a regular file") {
		t.Errorf("stderr should say the sidecar isn't a regular file specifically; got %q", res.stderr)
	}
}

func TestCheckSource_Match(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a match; got %q", res.stdout)
	}
}

// TestCheckSource_Match_WithSafeBareRepositoryExplicit: with a
// real user gitconfig setting [safe] bareRepository = explicit (which a
// developer or CI runner may well have set), `git -C <bare-dir>` fails with
// "cannot use bare repository" because `-C` only changes directory and lets
// git DISCOVER the repo there — exactly what that setting refuses for
// anything but an explicitly named git dir. verify_sha_on_upstream's
// ancestry check uses a throwaway BARE scratch repo, so without
// --git-dir instead of -C, check-source/sync would ALWAYS fail closed
// (exit 8/12) on such a machine, never actually verifying anything.
func TestCheckSource_Match_WithSafeBareRepositoryExplicit(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	env := envWithHomeGitConfig(t, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), "[safe]\n\tbareRepository = explicit\n")

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (safe.bareRepository=explicit must not break the ancestry check's bare scratch repo); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a match; got %q", res.stdout)
	}
}

// TestCheckSource_Match_FromDeletedCwd: `--git-dir="$scratch"` alone still
// leaves the process cwd as whatever the caller's was, and git's own setup
// calls getcwd() early regardless of --git-dir — if that cwd has since been
// removed (not unusual for a long-running orchestration process that cleans
// up its own working directory), the call fails with "Unable to read
// current working directory" even though it never needed the cwd for
// anything, causing a false refusal (exit 8). The fix also passes
// -C "$scratch" (a directory that, unlike the caller's cwd, is guaranteed
// to exist) alongside --git-dir. Removes the cwd right after starting the
// process — deterministic, not a race, since nothing in --check-source's
// match path ever chdirs elsewhere afterward.
func TestCheckSource_Match_FromDeletedCwd(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	requireEwaitTools(t)
	deletedCwd := t.TempDir()
	cmd := exec.Command("bash", append([]string{scriptPath}, "--check-source")...)
	cmd.Dir = deletedCwd
	cmd.Env = testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	)
	setNewProcessGroup(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start herdr-ewait.sh: %v", err)
	}
	if err := os.RemoveAll(deletedCwd); err != nil {
		t.Fatalf("remove the running process's cwd: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	proc := &ewaitProcess{cmd: cmd, stdout: &stdout, stderr: &stderr, done: done}
	res := proc.wait(t, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (match from a deleted cwd); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a match; got %q", res.stdout)
	}
}

func TestCheckSource_Drift(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\necho different\n"))

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceDrift {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceDrift, res.stdout, res.stderr)
	}
	// Both hashes must be printed, and they must be two DIFFERENT 64-hex-char values.
	hashes := sha256HexPattern.FindAllString(res.stderr, -1)
	if len(hashes) < 2 {
		t.Fatalf("stderr should contain two sha256 hashes on drift; got %q", res.stderr)
	}
	if hashes[0] == hashes[1] {
		t.Errorf("the two printed hashes must differ on a real drift; got %q twice", hashes[0])
	}
}

func TestCheckSource_FetchFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// rawBase exists but has no fixture file at all under it -> curl fails closed.
	rawBase := t.TempDir()

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
}

func TestCheckSource_InvalidSidecarFields(t *testing.T) {
	cases := []struct {
		name string
		repo string
		path string
		sha  string
	}{
		{"bad repo charset", "../etc/passwd", fakeScriptRelPath, strings.Repeat("a", 40)},
		{"repo segment starts with dot", "owner/.hidden", fakeScriptRelPath, strings.Repeat("a", 40)},
		{"path traversal", fakeRepo, "scripts/../../../etc/passwd", strings.Repeat("a", 40)},
		{"leading slash path", fakeRepo, "/etc/passwd", strings.Repeat("a", 40)},
		{"empty path segment", fakeRepo, "scripts//herdr-ewait.sh", strings.Repeat("a", 40)},
		{"path starts with dot", fakeRepo, ".hidden/herdr-ewait.sh", strings.Repeat("a", 40)},
		{"path with shell metacharacter", fakeRepo, "scripts/herdr-ewait.sh;rm -rf", strings.Repeat("a", 40)},
		{"bad sha length", fakeRepo, fakeScriptRelPath, "abc123"},
		{"bad sha charset", fakeRepo, fakeScriptRelPath, strings.Repeat("g", 40)},
		{"uppercase sha", fakeRepo, fakeScriptRelPath, strings.Repeat("A", 40)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := copyScriptToDir(t, dir)
			writeSidecar(t, dir, tc.repo, tc.path, tc.sha)

			// Defense in depth: even with the test hook active and pointed at a
			// local, empty fixture tree (for BOTH the raw-content fetch and the
			// ancestry check's git remote), validation must reject BEFORE ever
			// building a fetch/remote URL from these attacker-controlled fields
			// — so a regression here still can't reach the real network.
			emptyRaw := t.TempDir()
			emptyRemote := t.TempDir()
			res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
				"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(emptyRaw),
				"HERDR_EWAIT_REMOTE_BASE_URL="+emptyRemote,
			), 10*time.Second)

			if res.exitCode != exitCheckSourceFail {
				t.Fatalf("exit = %d, want %d (invalid sidecar); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
			}
			// "invalid repo/path/sha fields" is specific to validate_sidecar_fields's
			// own rejection — a bare "invalid" could also appear from an unrelated
			// downstream failure if this guard regressed.
			if !strings.Contains(res.stderr, "invalid repo/path/sha fields") {
				t.Errorf("stderr should say the sidecar fields are invalid specifically (not some other refusal); got %q", res.stderr)
			}
		})
	}
}

func TestCheckSource_Latest_Newer(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, oldSHA, fakeScriptRelPath, scriptBytes)
	// The file's content at the new head must actually be DIFFERENT for this to be
	// upstream-newer: a commit-only move with unchanged content is exit 0.
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\necho upstream-changed\n"))

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceUpstreamNewer {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceUpstreamNewer, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, oldSHA[:7]) {
		t.Errorf("stderr should mention the pinned sha; got %q", res.stderr)
	}
}

func TestCheckSource_Latest_CommitMovedFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	rawBase := t.TempDir()
	// Same content at both commits: the upstream default branch moved, but THIS
	// FILE did not change — must be exit 0, not upstream-newer.
	writeRawFixture(t, rawBase, fakeRepo, oldSHA, fakeScriptRelPath, scriptBytes)
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (commit moved, file unchanged); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "unchanged") {
		t.Errorf("stderr should note the file is unchanged despite the commit move; got %q", res.stderr)
	}
}

func TestCheckSource_Latest_NotNewer(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_AncestryCheck_NotReachable(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, _, _ := setupFakeRemote(t, fakeRepo)
	// Well-formed, but not an object that exists anywhere in the fake remote.
	bogusSHA := strings.Repeat("d", 40)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, bogusSHA)

	rawBase := t.TempDir() // never reached: ancestry must fail first
	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (sha not reachable from upstream); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	// "could not confirm" is the ancestry-check-specific message; a bare substring
	// like "reachable" would spuriously match this TEST'S OWN NAME, which t.TempDir()
	// embeds in paths that appear even in an unrelated fetch-failure message.
	if !strings.Contains(strings.ToLower(res.stderr), "could not confirm") {
		t.Errorf("stderr should explain the sha isn't confirmed reachable (ancestry check specifically, not some other failure); got %q", res.stderr)
	}
}

func TestCheckSource_EmptyHashOutput_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("anything\n"))

	stubDir := t.TempDir()
	writeFakeEmptyHashTool(t, stubDir)

	env := hermeticEnvCustomPath(t, stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HERDR_EWAIT_TEST_HOOKS=1",
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (empty hash output must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
}

func TestCheckSource_TestHookGate(t *testing.T) {
	cases := []struct {
		name             string
		setGate          bool
		wantRawSubstr    string
		wantRemoteSubstr string
		wantProto        string
	}{
		{"gate off: overrides ignored, real hosts targeted", false, "raw.githubusercontent.com", "github.com", "--proto =https "},
		{"gate on: local overrides honoured", true, "RAW_MARKER_XYZ", "REMOTE_MARKER_XYZ", "--proto =https,file,http "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := copyScriptToDir(t, dir)
			writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

			stubDir := t.TempDir()
			logPath := filepath.Join(t.TempDir(), "calls.log")
			// git "succeeds" unconditionally (so the flow reaches the curl fetch
			// regardless of which base it targeted) while logging its args; curl
			// always "fails" but also logs its args. Neither performs any real
			// git/network operation, so this is safe under gate-off too.
			writeFakeGit(t, stubDir, logPath)
			writeFakeCurl(t, stubDir, logPath)

			env := []string{
				"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
				"TMPDIR=" + t.TempDir(),
				"HERDR_EWAIT_RAW_BASE_URL=file:///RAW_MARKER_XYZ",
				"HERDR_EWAIT_REMOTE_BASE_URL=/REMOTE_MARKER_XYZ",
			}
			if tc.setGate {
				env = append(env, "HERDR_EWAIT_TEST_HOOKS=1")
			}

			res := runEwaitScript(t, scriptPath, []string{"--check-source"}, env, 10*time.Second)
			if res.exitCode != exitCheckSourceFail {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
			}

			logged, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read call log: %v", err)
			}
			if !strings.Contains(string(logged), tc.wantRawSubstr) {
				t.Errorf("curl should have targeted %q; log:\n%s", tc.wantRawSubstr, logged)
			}
			if !strings.Contains(string(logged), tc.wantRemoteSubstr) {
				t.Errorf("git should have targeted %q; log:\n%s", tc.wantRemoteSubstr, logged)
			}
			if !strings.Contains(string(logged), tc.wantProto) {
				t.Errorf("curl should have been invoked with %q; log:\n%s", tc.wantProto, logged)
			}

			// Checked per-variable (not just "a warning appeared somewhere"): the
			// raw and remote overrides are resolved by two separate functions, so a
			// regression dropping just ONE of their warnings must not be masked by
			// the other still firing.
			hasRawWarning := strings.Contains(res.stderr, "WARNING: test override active") && strings.Contains(res.stderr, "(HERDR_EWAIT_RAW_BASE_URL)")
			hasRemoteWarning := strings.Contains(res.stderr, "WARNING: test override active") && strings.Contains(res.stderr, "(HERDR_EWAIT_REMOTE_BASE_URL)")
			if tc.setGate && !(hasRawWarning && hasRemoteWarning) {
				t.Errorf("stderr should warn for BOTH overrides when active; got %q", res.stderr)
			}
			if !tc.setGate && (hasRawWarning || hasRemoteWarning) {
				t.Errorf("stderr must not warn when the test-hook gate is off; got %q", res.stderr)
			}
		})
	}
}

func TestCheckSource_TestHookRejectsArbitraryHost(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	stubDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls.log")
	writeFakeGit(t, stubDir, logPath) // ancestry must "pass" to reach raw-base resolution
	curlLog := filepath.Join(t.TempDir(), "curl.log")
	writeFakeCurl(t, stubDir, curlLog) // defense-in-depth: prove curl is never reached

	env := []string{
		"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HERDR_EWAIT_TEST_HOOKS=1",
		"HERDR_EWAIT_RAW_BASE_URL=http://evil.example.com",
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "must be file://") {
		t.Errorf("stderr should explain the allowed override forms; got %q", res.stderr)
	}
	if _, err := os.Stat(curlLog); err == nil {
		t.Errorf("curl was invoked — an arbitrary-host override must be rejected before any fetch")
	}
}

func TestCheckSource_TestHookRejectsUserinfoHost(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	stubDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls.log")
	writeFakeGit(t, stubDir, logPath) // ancestry must "pass" to reach raw-base resolution
	curlLog := filepath.Join(t.TempDir(), "curl.log")
	writeFakeCurl(t, stubDir, curlLog) // defense-in-depth: prove curl is never reached

	env := []string{
		"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HERDR_EWAIT_TEST_HOOKS=1",
		// A glob like "localhost:[0-9]*" would wrongly accept this; the anchored
		// regex must not, since '@' introduces userinfo naming a different host.
		"HERDR_EWAIT_RAW_BASE_URL=http://localhost:1@evil.example.com",
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (userinfo host must be refused); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "must be file://") {
		t.Errorf("stderr should explain the allowed override forms; got %q", res.stderr)
	}
	if _, err := os.Stat(curlLog); err == nil {
		t.Errorf("curl was invoked — a userinfo-bearing host override must be rejected before any fetch")
	}
}

func TestCheckSource_RawBaseAbsolutePath_ConvertedToFileURL(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir() // bare absolute path, no file:// prefix
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBase,
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (a bare absolute path must work for the raw base too, converted to file:// internally); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- self-path resolution hardening ---

func TestCheckSource_CDPathDoesNotCorruptSelfPath(t *testing.T) {
	scriptParent := t.TempDir()
	const scriptSubdir = "vendored"
	realDir := filepath.Join(scriptParent, scriptSubdir)
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := copyScriptToDir(t, realDir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, realDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	// CDPATH names scriptParent, so bash's `cd vendored` (inside script_self_path,
	// since $0 is invoked as the relative "vendored/herdr-ewait.sh" below) matches
	// via CDPATH and, without the CDPATH= guard, PRINTS the matched directory to
	// stdout — corrupting the command substitution with an extra line, which would
	// make sidecar_state() look in the wrong place and report "absent" instead of
	// finding the real sidecar.
	env := append(testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), "CDPATH="+scriptParent)

	res := runRelative(t, scriptParent, filepath.Join(scriptSubdir, "herdr-ewait.sh"), []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (CDPATH must not corrupt self-path resolution); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a clean match, not be corrupted by a CDPATH-printed line; got %q", res.stdout)
	}
}

// TestCheckSource_Refuse_SymlinkedScript: a bare
// "symlink" substring check is a false-positive-pass trap here — this test's
// own name, "TestCheckSource_Refuse_SymlinkedScript", is embedded by
// t.TempDir() into the dead-hook-env's "unreachable" path, and lowercasing
// "Symlinked" also produces the substring "symlink" — so even if the real
// symlink-refusal guard were bypassed and execution fell through to the
// ancestry-check failure message (which prints that same temp path), the
// bare substring check would still spuriously pass. Anchor on the exact
// refusal message instead, AND prove the failure happens before any network
// call by recording curl invocations on a fake curl and asserting it was
// never invoked (deadHookEnv's dead path alone doesn't prove curl was never
// even attempted).
func TestCheckSource_Refuse_SymlinkedScript(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-herdr-ewait.sh")
	if err := os.WriteFile(realPath, realScriptBytes(t), 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "herdr-ewait.sh")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	stubDir := t.TempDir()
	curlLog := filepath.Join(t.TempDir(), "curl.log")
	writeFakeCurl(t, stubDir, curlLog)
	env := deadHookEnv(t)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runEwaitScript(t, linkPath, []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (symlinked check-source must refuse, same rule as --sync); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is a symlink; check-source must run against the real file, not a symlink") {
		t.Errorf("stderr should contain the specific symlink-refusal message (not merely the word 'symlink', which a bypassed guard could still satisfy via this test's own name embedded in an unrelated path); got %q", res.stderr)
	}
	if _, err := os.Stat(curlLog); err == nil {
		t.Errorf("curl was invoked — the symlink refusal must happen before any fetch/network call")
	}
}

func TestCheckSource_ExpectVendored_NoSidecar(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-vendored"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceExpectVendored {
		t.Fatalf("exit = %d, want %d (expected a vendored copy, found none); stdout=%q stderr=%q", res.exitCode, exitCheckSourceExpectVendored, res.stdout, res.stderr)
	}
}

func TestCheckSource_ExpectVendored_WithSidecar_NormalMatch(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-vendored"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (a real sidecar present satisfies --expect-vendored); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_ExpectVendored_LatestOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	for _, args := range [][]string{
		{"--check-source", "--expect-vendored", "--latest"},
		{"--check-source", "--latest", "--expect-vendored"},
	} {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceExpectVendored {
			t.Errorf("args %v: exit = %d, want %d; stdout=%q stderr=%q", args, res.exitCode, exitCheckSourceExpectVendored, res.stdout, res.stderr)
		}
	}
}

// --- default-branch refusal / git_safe hardening ---

// TestSync_GitSafe_ScrubsPoisonedGitEnv asserts directly on what environment
// reaches `git`, rather than on a behavioral symptom — a poisoned var that
// happens to be one of the obvious four (GIT_DIR et al.) would already be
// caught by a much narrower scrub, giving a false sense of coverage. A `git`
// stub dumps its own environment before delegating to the real binary.
func TestSync_GitSafe_ScrubsPoisonedGitEnv(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	initGitRepoWithDefaultBranch(t, dir)

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found in PATH")
	}
	stubDir := t.TempDir()
	dumpPath := filepath.Join(t.TempDir(), "env-dump.txt")
	script := "#!/usr/bin/env bash\n" +
		"env | grep '^GIT_' >> '" + dumpPath + "' || true\n" +
		"exec '" + realGit + "' \"$@\"\n"
	writeExec(t, filepath.Join(stubDir, "git"), script)

	env := []string{
		"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		// Not one of the "obvious four" (GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE/
		// GIT_COMMON_DIR) — a scrub limited to just those would let this through.
		"GIT_WEIRD_POISON_VAR=should-not-reach-git",
	}
	if home := os.Getenv("HOME"); home != "" {
		env = append(env, "HOME="+home)
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, env, 10*time.Second)
	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d ($dir is on its default branch); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}

	dumped, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("read env dump: %v", err)
	}
	if strings.Contains(string(dumped), "GIT_WEIRD_POISON_VAR") {
		t.Errorf("git_safe let GIT_WEIRD_POISON_VAR reach git — not every GIT_* var is scrubbed; dumped env:\n%s", dumped)
	}
	if !strings.Contains(string(dumped), "GIT_CONFIG_NOSYSTEM=1") {
		t.Errorf("git_safe should itself set GIT_CONFIG_NOSYSTEM=1; dumped env:\n%s", dumped)
	}
	if !strings.Contains(string(dumped), "GIT_TERMINAL_PROMPT=0") {
		t.Errorf("git_safe should itself set GIT_TERMINAL_PROMPT=0; dumped env:\n%s", dumped)
	}
}

func TestSync_Refuse_RevParseFailsInsideRealTree(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir)
	// Corrupt .git/HEAD so `git rev-parse --is-inside-work-tree` itself fails even
	// though $dir is genuinely inside a git work tree — the "git missing" upward
	// .git scan must ALSO cover this case, not just git being entirely absent.
	headFile := filepath.Join(dir, ".git", "HEAD")
	if err := os.WriteFile(headFile, []byte("not a valid HEAD file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (rev-parse failing inside a real tree must still refuse, not fall open); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
}

// --- sidecar parsing: fail closed on duplicate/unknown keys ---

func TestCheckSource_Refuse_DuplicateSidecarKey(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	content := "repo=" + fakeRepo + "\npath=" + fakeScriptRelPath + "\nsha=" + strings.Repeat("a", 40) + "\nsha=" + strings.Repeat("b", 40) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "herdr-ewait.source"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (duplicate sidecar key must fail closed, not last-wins); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stderr), "malformed") {
		t.Errorf("stderr should say the sidecar is malformed; got %q", res.stderr)
	}
}

func TestCheckSource_Refuse_UnknownSidecarKey(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	// A fully working match setup (reachable sha, matching content): if the
	// unknown key were silently ignored instead of failing closed, this would
	// otherwise succeed (exit 0) — isolating the guard as the sole discriminator,
	// not relying on a shared "exit 8" bucket that an unrelated failure could also
	// coincidentally land on.
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	content := "repo=" + fakeRepo + "\npath=" + fakeScriptRelPath + "\nsha=" + headSHA + "\nextra=whatever\n"
	if err := os.WriteFile(filepath.Join(dir, "herdr-ewait.source"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (unknown sidecar key must fail closed, not be ignored — an otherwise-perfect match setup); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stderr), "malformed") {
		t.Errorf("stderr should say the sidecar is malformed; got %q", res.stderr)
	}
}

func TestSync_Refuse_DuplicateSidecarKey(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	content := "repo=" + fakeRepo + "\nrepo=another/repo\npath=" + fakeScriptRelPath + "\nsha=" + strings.Repeat("a", 40) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "herdr-ewait.source"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (duplicate sidecar key must fail closed); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	// exit 12 is shared with several other refusals (download/ancestry failure) —
	// pin down the malformed-sidecar message specifically, so a last-wins
	// regression that happens to fail later for an unrelated reason (e.g. trying
	// to resolve/fetch "another/repo") isn't mistaken for this guard holding.
	if !strings.Contains(strings.ToLower(res.stderr), "malformed") {
		t.Errorf("stderr should say the sidecar is malformed; got %q", res.stderr)
	}
}

// --- static-only content checks (bash "$f" --help removed) ---

func TestSync_Refuse_OversizedDownload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	var big strings.Builder
	big.WriteString("#!/usr/bin/env bash\n")
	big.WriteString(`readonly SIDECAR_NAME="herdr-ewait.source"` + "\n")
	for big.Len() < 1048576+1024 {
		big.WriteString("# padding padding padding padding padding padding padding\n")
	}
	big.WriteString("# herdr-ewait: end of file\n")

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte(big.String()))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (oversized download must be refused); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_TruncatedDownload_MissingEOFSentinel(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// Shebang + sentinel present, but missing the trailing end-of-file sentinel —
	// simulates a response truncated mid-download.
	content := "#!/usr/bin/env bash\n" + `readonly SIDECAR_NAME="herdr-ewait.source"` + "\necho truncated\n"
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte(content))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (truncated download missing the EOF sentinel must be refused); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_NeverExecutesDownloadedContent(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// Shebang, sentinel, and EOF sentinel all present (passes every static check),
	// but if this were ever EXECUTED it would write a proof file — confirming the
	// removal of "bash $f --help" by checking that file never appears.
	proof := filepath.Join(dir, "proof-of-execution")
	content := "#!/usr/bin/env bash\n" +
		`readonly SIDECAR_NAME="herdr-ewait.source"` + "\n" +
		"touch " + proof + "\n" +
		"# herdr-ewait: end of file\n"
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte(content))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (content is static-valid); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if _, err := os.Stat(proof); err == nil {
		t.Fatalf("downloaded content was EXECUTED (proof file exists) — a bash --help regression")
	}
}

func TestSync_Refuse_BashNGate_WithBothSentinelsPresent(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// Isolates the bash -n gate specifically: both sentinels are present (so
	// looks_like_ewait_script's static string checks alone would NOT catch this),
	// but the content is syntactically broken.
	content := "#!/usr/bin/env bash\n" +
		`readonly SIDECAR_NAME="herdr-ewait.source"` + "\n" +
		"if true; then\necho unterminated\n" +
		"# herdr-ewait: end of file\n"
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte(content))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "bash -n") {
		t.Errorf("stderr should specifically name the bash -n failure (sentinels alone wouldn't catch this); got %q", res.stderr)
	}
}

// --- --latest sub-failures, each distinctly ---

// gitPassthroughExceptLsRemote installs a `git` stub on stubDir that fails ONLY a
// bare `ls-remote` call (used by resolve_remote_ref, i.e. --latest's own
// default-branch-head resolution and --sync main) and delegates every other
// subcommand (init/fetch/merge-base/etc., used by the ancestry check) to the real
// git — isolating a ls-remote-specific failure from an ancestry-check failure, which
// otherwise share the same remote and would fail together.
func gitPassthroughExceptLsRemote(t *testing.T, stubDir string) {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found in PATH")
	}
	// git_safe always prepends "-c ..." flags, so "ls-remote" is not necessarily
	// $1 — scan every argument instead of assuming a fixed position.
	script := "#!/usr/bin/env bash\n" +
		"has_ls_remote=0; has_symref=0\n" +
		"for a in \"$@\"; do\n" +
		"  [ \"$a\" = \"ls-remote\" ] && has_ls_remote=1\n" +
		"  [ \"$a\" = \"--symref\" ] && has_symref=1\n" +
		"done\n" +
		"if [ \"$has_ls_remote\" -eq 1 ] && [ \"$has_symref\" -eq 0 ]; then exit 1; fi\n" +
		"exec '" + realGit + "' \"$@\"\n"
	writeExec(t, filepath.Join(stubDir, "git"), script)
}

func TestCheckSource_Latest_LsRemoteFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	stubDir := t.TempDir()
	gitPassthroughExceptLsRemote(t, stubDir)

	env := testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (--latest's own ls-remote failing, after a successful match, must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	// Pin down that it's specifically the empty-head_sha guard firing (not just
	// coincidentally failing later at the head-content fetch with an empty sha
	// spliced into the URL, which a removed guard would still often trip too).
	if !strings.Contains(res.stderr, "failed to resolve the default-branch head") {
		t.Errorf("stderr should name the ls-remote/head-resolution failure specifically; got %q", res.stderr)
	}
}

func TestCheckSource_Latest_HeadFetchFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)
	rawBase := t.TempDir()
	// Fixture only at oldSHA (for the match step) — none at headSHA, so the
	// --latest content-fetch specifically fails.
	writeRawFixture(t, rawBase, fakeRepo, oldSHA, fakeScriptRelPath, scriptBytes)
	_ = headSHA

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (fetching the file at the upstream head must fail closed, not report upstream-newer or a false match); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
}

// writeFlakyHashTool installs a `sha256sum` on stubDir that delegates to the real
// tool for its first failAfter-1 calls, then prints nothing (exit 0) from
// call number failAfter onward — isolates a hash failure at one specific step
// (e.g. --latest's OWN head-content hash) from the earlier steps that must still
// succeed normally (match's remote/local hash) for the test to be meaningful.
func writeFlakyHashTool(t *testing.T, stubDir string, counterFile string, failAfter int) {
	t.Helper()
	realPath, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("sha256sum not found in PATH")
	}
	script := "#!/usr/bin/env bash\n" +
		"n=0\n" +
		"[ -f '" + counterFile + "' ] && n=$(cat '" + counterFile + "')\n" +
		"n=$((n+1))\n" +
		"echo \"$n\" > '" + counterFile + "'\n" +
		"if [ \"$n\" -ge " + strconv.Itoa(failAfter) + " ]; then exit 0; fi\n" +
		"exec '" + realPath + "' \"$@\"\n"
	writeExec(t, filepath.Join(stubDir, "sha256sum"), script)
}

func TestCheckSource_Latest_EmptyHeadHash(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, oldSHA, fakeScriptRelPath, scriptBytes)
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("different content at head\n"))

	stubDir := t.TempDir()
	counterFile := filepath.Join(t.TempDir(), "hash-call-counter")
	// Calls 1-2 (remote_hash, local_hash — the match step) succeed normally; call 3
	// (head_hash, --latest's own content hash) gets empty output.
	writeFlakyHashTool(t, stubDir, counterFile, 3)

	env := testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (empty head-content hash must fail closed, not report a false match or upstream-newer); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "could not hash the upstream-head content") {
		t.Errorf("stderr should name the head-hash step specifically; got %q", res.stderr)
	}
}

// --- --sync ---

// TestSync_Success_WithSafeBareRepositoryExplicit: the --sync
// counterpart of TestCheckSource_Match_WithSafeBareRepositoryExplicit — see
// its doc comment for why safe.bareRepository=explicit would otherwise break
// the ancestry check's bare scratch repo.
func TestSync_Success_WithSafeBareRepositoryExplicit(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	newContent := fakeUpstreamScript(t, "safe-bare-repository-explicit")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	env := envWithHomeGitConfig(t, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), "[safe]\n\tbareRepository = explicit\n")

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, env, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (safe.bareRepository=explicit must not break the ancestry check's bare scratch repo); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Errorf("script file not replaced; got %q", got)
	}
}

func TestSync_Success_ExplicitSHA(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	if err := os.Chmod(scriptPath, 0o744); err != nil {
		t.Fatal(err)
	}
	oldInode := inode(t, scriptPath)

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	newContent := fakeUpstreamScript(t, "explicit-sha")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, oldSHA) || !strings.Contains(res.stdout, headSHA) {
		t.Errorf("stdout should print old and new sha; got %q", res.stdout)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Errorf("script file not replaced; got %q", got)
	}
	if inode(t, scriptPath) == oldInode {
		t.Errorf("inode unchanged — the file was edited in place instead of atomically replaced")
	}

	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o744 {
		t.Errorf("permissions not preserved: got %o, want %o", info.Mode().Perm(), 0o744)
	}

	sidecarData, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecarData), "sha="+headSHA) {
		t.Errorf("sidecar sha not rewritten; got %q", sidecarData)
	}
	if strings.Contains(string(sidecarData), "sha="+oldSHA) {
		t.Errorf("sidecar still contains old sha; got %q", sidecarData)
	}
	if !strings.Contains(string(sidecarData), "repo="+fakeRepo) {
		t.Errorf("sidecar should keep repo= unchanged; got %q", sidecarData)
	}
}

func TestSync_Success_Main(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	newContent := fakeUpstreamScript(t, "main")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", "main"}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Errorf("script file not replaced with resolved main head; got %q", got)
	}
	sidecarData, _ := os.ReadFile(sidecarPath)
	if !strings.Contains(string(sidecarData), "sha="+headSHA) {
		t.Errorf("sidecar sha should be rewritten to resolved main head %s; got %q", headSHA, sidecarData)
	}
}

func TestSync_Success_OnNonDefaultBranch(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	initGitRepoWithDefaultBranch(t, dir)
	gitCmd(t, dir, "checkout", "-q", "-b", "feature/sync-test")

	newContent := fakeUpstreamScript(t, "feature-branch")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (non-default branch must be allowed); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_NoSidecar(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncNoSidecar {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncNoSidecar, res.stdout, res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

func TestSync_Refuse_SidecarIrregular(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "herdr-ewait.source"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (irregular sidecar); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	// See TestCheckSource_SidecarIrregular_IsError: exit 12 is shared with several
	// other sync refusals, so pin down the irregular-specific message too.
	if !strings.Contains(res.stderr, "not a regular file") {
		t.Errorf("stderr should say the sidecar isn't a regular file specifically; got %q", res.stderr)
	}
}

func TestSync_Refuse_OnDefaultBranch(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Refuse_OnDefaultBranch_WithLocalBranchNamedOriginMain and
// TestSync_Refuse_OnDefaultBranch_WithTagNamedMain: default_branch_of
// used `symbolic-ref --short refs/remotes/origin/HEAD` and cmd_sync used
// `symbolic-ref --short HEAD` — `--short` abbreviates to the SHORTEST
// UNAMBIGUOUS name, which depends on what else exists in the repo. A local
// branch literally named "origin/main" makes refs/remotes/origin/HEAD (which
// points at refs/remotes/origin/main) shorten to "remotes/origin/main"
// instead of "origin/main", silently breaking the old "${ref#origin/}"
// strip; a tag literally named "main" makes plain HEAD (refs/heads/main)
// shorten to "heads/main" instead of "main" to disambiguate from the tag.
// Either one broke the `current = default_branch` comparison and let --sync
// run on the real default branch undetected. Both must still refuse (exit
// 11) and leave the script file untouched.
func TestSync_Refuse_OnDefaultBranch_WithLocalBranchNamedOriginMain(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main", current HEAD
	// A local branch literally named "origin/main" (never checked out) is
	// enough to make refs/remotes/origin/HEAD's --short form ambiguous.
	gitCmd(t, dir, "branch", "origin/main")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (a local branch named origin/main must not let --sync bypass the default-branch refusal); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

func TestSync_Refuse_OnDefaultBranch_WithTagNamedMain(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main", current HEAD
	// A tag literally named "main" is enough to make HEAD's --short form
	// ambiguous with refs/heads/main.
	gitCmd(t, dir, "tag", "main")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (a tag named main must not let --sync bypass the default-branch refusal); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback and its
// _WithAmbiguousRefs variant cover default_branch_of's SECOND resolution
// path — `git ls-remote --symref origin HEAD` against a real 'origin'
// remote — which the --short-ambiguity tests above never exercise (they all
// go through the first path, refs/remotes/origin/HEAD recorded locally).
// Mutating this fallback's `case "$ref" in refs/heads/?*)` guard to print
// the unstripped "refs/heads/main" (instead of stripping the prefix) made
// the whole suite pass regardless, because nothing else drove this code
// path at all.
func TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main", current HEAD
	dropLocalOriginHeadRef(t, dir)
	bareOrigin := setupLocalBareOrigin(t)
	gitCmd(t, dir, "remote", "add", "origin", bareOrigin)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (ls-remote --symref fallback must still refuse on the default branch); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback_WithAmbiguousRefs
// adds a tag named "main" AND a local branch named "origin/main" on top of
// the fallback setup above — both of which make `--short` forms ambiguous
// (see the WithLocalBranchNamedOriginMain/WithTagNamedMain tests) — to
// confirm the ls-remote --symref fallback's full-ref parsing isn't itself
// vulnerable to the same kind of ambiguity the --short-based code was.
func TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback_WithAmbiguousRefs(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main", current HEAD
	dropLocalOriginHeadRef(t, dir)
	bareOrigin := setupLocalBareOrigin(t)
	gitCmd(t, dir, "remote", "add", "origin", bareOrigin)
	// Create the branch BEFORE the tag: once a branch and a tag share the
	// same name, "main" is ambiguous for every later git command that
	// resolves it for any reason (not just --short abbreviation — plain
	// `git branch <newname>` with no explicit start-point fails outright
	// once that ambiguity exists), so the branch must exist first.
	gitCmd(t, dir, "branch", "origin/main")
	gitCmd(t, dir, "tag", "main")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (ambiguous refs must not defeat the ls-remote --symref fallback either); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback_WithDecoySymref
// covers a server (or just a repo state) that advertises a SECOND symref
// whose name also ends in "/HEAD" (e.g. a tag or branch literally named
// "HEADtag"/"HEADx") alongside the real "HEAD" one — `ls-remote --symref
// origin HEAD` doesn't exactly-match the ref name it was asked for, so both
// get reported as separate "ref: ..." lines. Before filtering on the ref
// NAME (not just the literal word "ref:"), the combined multi-line value
// matched the "refs/heads/?*" glob as a whole (bash globs don't treat
// embedded newlines specially) and left a garbled "default_branch" that
// never equaled the actual current branch — silently defeating the refusal
// and letting --sync proceed on the real default branch.
func TestSync_Refuse_OnDefaultBranch_ViaLsRemoteSymrefFallback_WithDecoySymref(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main", current HEAD
	dropLocalOriginHeadRef(t, dir)
	bareOrigin := setupLocalBareOrigin(t)
	gitCmd(t, dir, "remote", "add", "origin", bareOrigin)
	// A decoy symref whose name also ends in "/HEAD", advertised by the same
	// remote alongside the real HEAD.
	gitCmd(t, bareOrigin, "symbolic-ref", "refs/tags/HEADtag/HEAD", "refs/heads/main")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (a decoy symref ending in /HEAD must not defeat the ls-remote --symref fallback); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Success_OnFeatureBranch_ViaLsRemoteSymrefFallback is the control:
// the same ls-remote --symref fallback setup, but on a feature branch, which
// must proceed PAST the default-branch refusal (it still fails later, at the
// ancestry check, because deadHookEnv's test hooks point nowhere — that
// failure, exitSyncBadDownload rather than exitSyncOnDefaultBranch, is what
// proves the refusal check itself let it through).
func TestSync_Success_OnFeatureBranch_ViaLsRemoteSymrefFallback(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir)
	dropLocalOriginHeadRef(t, dir)
	bareOrigin := setupLocalBareOrigin(t)
	gitCmd(t, dir, "remote", "add", "origin", bareOrigin)
	gitCmd(t, dir, "checkout", "-q", "-b", "feature/sync-test")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode == exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d (on-default-branch refusal), want anything else — a feature branch must pass the refusal check; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// TestSync_Refuse_OnDefaultBranch_CaseInsensitiveCheckout covers the
// case-insensitive-filesystem gap: on APFS (macOS's default), `git checkout
// Main` resolves to the SAME loose ref file as an existing "main" branch,
// but leaves HEAD symbolically pointing at the literal string
// "refs/heads/Main" — textually different from default_branch_of's "main".
// An exact-string comparison would treat that as a different, non-default
// branch and wrongly let --sync proceed on what is, on that filesystem,
// genuinely the repo's protected default branch. The fix folds case on both
// sides of the comparison unconditionally (see cmd_sync's comment) rather
// than only on a detected case-insensitive filesystem — the simplest choice
// that is safe everywhere, documented there as an intentional, slightly
// more conservative refusal on any repo with two case-differing branch
// names on a case-sensitive filesystem too.
func TestSync_Refuse_OnDefaultBranch_CaseInsensitiveCheckout(t *testing.T) {
	if filesystemIsCaseSensitive(t) {
		t.Skip("filesystem is case-sensitive; 'git checkout Main' would need an actual distinct 'Main' branch to reproduce this, not the same-file collision this test targets")
	}

	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir) // creates+checks out "main"
	gitCmd(t, dir, "checkout", "-q", "Main")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (checking out 'Main' on a case-insensitive filesystem must still refuse as the default branch); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'main'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

// TestSync_Refuse_OnDefaultBranch_UnicodeCaseFold covers APFS's own
// Unicode-aware case folding, which `tr '[:upper:]' '[:lower:]'` under
// LC_ALL=C never replicates: "maſter" (long s, U+017F) resolves to the SAME
// loose ref file as "master" on such a filesystem, but is untouched by an
// ASCII-only fold, so the name comparison alone doesn't catch it — only the
// filesystem-identity (-ef) check does.
func TestSync_Refuse_OnDefaultBranch_UnicodeCaseFold(t *testing.T) {
	if filesystemIsCaseSensitive(t) {
		t.Skip("filesystem is case-sensitive; APFS's Unicode-aware case folding (the long s in 'maſter') doesn't collide with 'master' there")
	}

	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	gitCmd(t, dir, "init", "-q", "-b", "master")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init", "--allow-empty")
	headSHA := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	gitCmd(t, dir, "update-ref", "refs/remotes/origin/master", headSHA)
	gitCmd(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")
	gitCmd(t, dir, "checkout", "-q", "maſter")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (Unicode case folding on a case-insensitive filesystem must still refuse as the default branch); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is on 'master'") {
		t.Errorf("stderr should name the default branch; got %q", res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

func TestSync_Refuse_DetachedHead(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	initGitRepoWithDefaultBranch(t, dir)
	headSHA := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	gitCmd(t, dir, "checkout", "-q", headSHA)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (detached HEAD must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_OriginHeadUnset_NoOrigin(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	// A git work tree with NO refs/remotes/origin/HEAD recorded and no 'origin'
	// remote configured at all — default_branch_of() cannot determine the
	// default branch locally OR via the network, and must fail closed (refuse)
	// rather than guess "main"/"master", even on a branch named neither.
	gitCmd(t, dir, "init", "-q", "-b", "trunk")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init", "--allow-empty")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (undetermined default branch must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stderr), "could not determine") {
		t.Errorf("stderr should explain the default branch couldn't be determined; got %q", res.stderr)
	}
}

// TestSync_Refuse_SymlinkedScript: a bare
// "symlink" substring check is a false-positive-pass trap — this test's own
// name embeds "Symlinked", which lowercases to a string containing
// "symlink" and could spuriously satisfy the assertion via an unrelated
// message (e.g. one embedding this test's own t.TempDir() path). Anchor on
// the exact refusal message instead.
func TestSync_Refuse_SymlinkedScript(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-herdr-ewait.sh")
	if err := os.WriteFile(realPath, realScriptBytes(t), 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "herdr-ewait.sh")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, linkPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (symlinked script must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "is a symlink; sync must run against the real file, not a symlink") {
		t.Errorf("stderr should contain the specific symlink-refusal message; got %q", res.stderr)
	}
}

func TestSync_Refuse_GitMissingButInGitDir(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := withTempHome(t, hermeticEnvCustomPath(t, pathWithoutGit(t)))
	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, env, 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (git missing but inside a work tree must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
}

func TestSync_GitMissingNoRepo_SkipsBranchRefusal(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	env := withTempHome(t, hermeticEnvCustomPath(t, pathWithoutGit(t)))
	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, env, 10*time.Second)

	// git is unavailable, so the ancestry check (which also requires git) must
	// fail closed too — but NOT via the branch-refusal path, since there is no
	// .git anywhere above dir. Assert it's specifically the ancestry/bad-download
	// bucket, not the default-branch-refusal bucket.
	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (git missing, no repo above — ancestry check fails, not branch refusal); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_BadDownload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)
	sidecarBefore, _ := os.ReadFile(sidecarPath)

	rawBase := t.TempDir()
	// Syntactically invalid bash -> must fail `bash -n` and never be installed.
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\nif true; then\necho unterminated\n"))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be replaced when the download fails bash -n")
	}
	sidecarAfter, _ := os.ReadFile(sidecarPath)
	if string(sidecarBefore) != string(sidecarAfter) {
		t.Errorf("sidecar must not be rewritten on a refused sync")
	}
}

func TestSync_Refuse_EmptyDownload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte(""))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (empty download, bash -n would accept it); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

// TestSync_Refuse_MissingShebang: the original fixture
// ("echo hi\n") failed BOTH the shebang check AND the sentinel checks at
// once, so it couldn't tell "the shebang guard caught this" from "a sentinel
// guard would have caught it anyway" — a removed/broken shebang check would
// still pass this test. Give the fixture both sentinels (and valid bash
// syntax, so it clears `bash -n` first) but no shebang line, isolating the
// shebang guard specifically.
func TestSync_Refuse_MissingShebang(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath,
		[]byte("echo hi\nSIDECAR_NAME=\"herdr-ewait.source\"\n# herdr-ewait: end of file\n"))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (missing shebang); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_MissingSentinel(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	// Valid bash, right shebang, but not actually herdr-ewait.sh.
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\necho not-the-real-thing\n"))

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (missing sentinel); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_DownloadFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir() // nothing under it -> curl fails
	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_BadArgFormat(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync", "not-a-sha-or-main"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_NoArg(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (usage error, not an unbound-variable crash); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_Sync_CannotCombine(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	cases := [][]string{
		{"--check-source", "--targets", "w1:p1"},
		{"--sync", strings.Repeat("a", 40), "--log", "/tmp/x"},
		{"--check-source", "--sync", "main"},
		{"--targets", "w1:p1", "--check-source"},
	}
	for _, args := range cases {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (usage error); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

func TestSync_Refuse_InvalidSidecarFields(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, "../not/a/repo", fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (invalid sidecar); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	// Both sync's "no sidecar" and ancestry-check refusals also map to a non-zero
	// exit in the same family, so pin down the exact rejection reason too — this
	// phrase is unique to validate_sidecar_fields's own refusal.
	if !strings.Contains(res.stderr, "invalid repo/path/sha fields") {
		t.Errorf("stderr should say the sidecar fields are invalid specifically (not some other refusal); got %q", res.stderr)
	}
}

func TestSync_Refuse_AncestryCheck_NotReachable(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	remoteBase, oldSHA, _ := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	bogusSHA := strings.Repeat("d", 40)
	rawBase := t.TempDir() // never reached
	res := runEwaitScript(t, scriptPath, []string{"--sync", bogusSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (target sha not reachable from upstream); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
	// See TestCheckSource_AncestryCheck_NotReachable for why "could not confirm" is
	// used instead of a bare "reachable" substring (which spuriously matches this
	// test's own name as embedded by t.TempDir() in unrelated paths).
	if !strings.Contains(strings.ToLower(res.stderr), "could not confirm") {
		t.Errorf("stderr should explain the sha isn't confirmed reachable (ancestry check specifically, not some other failure); got %q", res.stderr)
	}
}

func TestSync_SidecarPermissionPreserved(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)
	if err := os.Chmod(sidecarPath, 0o640); err != nil {
		t.Fatal(err)
	}

	newContent := fakeUpstreamScript(t, "perm-test")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	info, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("sidecar permissions not preserved: got %o, want %o (mktemp default 0600 would indicate the bug)", info.Mode().Perm(), 0o640)
	}
}

// TestSync_Success_SidecarCommentHasInvalidUTF8Bytes:
// rewrite_sidecar_sha's leading-whitespace trim used to go through a `sed -E`
// pipeline in the CALLER's locale — under a real UTF-8 locale, a line
// containing invalid UTF-8 bytes (e.g. a non-ASCII comment line, perfectly
// legal in the key=value sidecar format since only comments and repo/path/sha
// lines are structurally meaningful) made sed fail with "illegal byte
// sequence"; since this call sits directly in cmd_sync's body (not inside a
// `||`-guarded conditional or assignment context the way load_sidecar's own
// trim is), `set -euo pipefail` took that as fatal and killed the whole
// script with an UNDOCUMENTED exit 1 instead of a clean, intentional outcome.
// Pins LANG/LC_ALL to a real UTF-8 locale (see availableUTF8Locale) so this
// actually exercises the bug's precondition rather than defaulting to C.
func TestSync_Success_SidecarCommentHasInvalidUTF8Bytes(t *testing.T) {
	loc := availableUTF8Locale(t)
	if loc == "" {
		t.Skip("no UTF-8 locale installed on this machine")
	}

	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)

	sidecarPath := filepath.Join(dir, "herdr-ewait.source")
	var buf bytes.Buffer
	buf.WriteString("# a comment line with invalid UTF-8 bytes: ")
	buf.Write([]byte{0xff, 0xfe})
	buf.WriteString("\n")
	buf.WriteString("repo=" + fakeRepo + "\n")
	buf.WriteString("path=" + fakeScriptRelPath + "\n")
	buf.WriteString("sha=" + oldSHA + "\n")
	if err := os.WriteFile(sidecarPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	newContent := fakeUpstreamScript(t, "utf8-comment")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	env := testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		"LANG="+loc, "LC_ALL="+loc,
	)
	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, env, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (an invalid-byte COMMENT line must not crash the sidecar rewrite under a UTF-8 locale); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	sidecarData, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecarData), "sha="+headSHA) {
		t.Errorf("sidecar sha not rewritten; got %q", sidecarData)
	}
	if !bytes.Contains(sidecarData, []byte{0xff, 0xfe}) {
		t.Errorf("the invalid-byte comment line must be preserved verbatim; got %q", sidecarData)
	}
}

// TestSync_DoesNotDisruptRunningInstance proves the atomic write-temp-then-mv
// replace is safe for an already-running instance: a wait-mode invocation
// started from scriptPath before the sync keeps running against its
// original (now-unlinked) inode and reaches its own normal exit, even though
// --sync replaces the file at that path while it's still executing.
func TestSync_DoesNotDisruptRunningInstance(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	oldInode := inode(t, scriptPath)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// "main" resolves to headSHA again here (no second commit needed): the point
	// of this test is concurrency safety, not which sha gets installed.
	newContent := fakeUpstreamScript(t, "while-running")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	stubDir := t.TempDir()
	writeHerdrStub(t, stubDir)
	logPath, cursorPath := newEwaitFiles(t)

	waitEnv := stubConfig{alwaysWorking: "w9:p1"}.env()
	waitEnv = append(waitEnv, "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	proc := startEwaitAt(t, scriptPath, []string{
		"--targets", "w9:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "4",
		"--poll", "1",
		"--safety-net", "4",
	}, waitEnv)

	time.Sleep(700 * time.Millisecond) // let it get into its poll loop first

	syncRes := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)
	if syncRes.exitCode != 0 {
		t.Fatalf("sync exit = %d, want 0; stdout=%q stderr=%q", syncRes.exitCode, syncRes.stdout, syncRes.stderr)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Fatalf("script file not replaced as expected")
	}
	if inode(t, scriptPath) == oldInode {
		t.Errorf("inode unchanged — not an atomic replace")
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 2 {
		t.Fatalf("running instance exit = %d, want 2 (overall timeout) — the in-flight process must keep running against its original inode; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// TestCheckSource_Refuse_BareNameFromWrongCwd/TestSync_Refuse_BareNameFromWrongCwd
// bash resolves a bare (no "/") script-file argument to `bash <name>` via a
// PATH search — confirmed experimentally — but leaves $0 as the bare name, NOT the
// resolved path. Without the bare-name $0 resolution fix, script_self_path would resolve
// dirname("$0")="." against the CALLER's cwd (which has no sidecar at all here),
// silently reporting "this copy is the source" for what is actually a drifted
// vendored copy found only via PATH.
func TestCheckSource_Refuse_BareNameFromWrongCwd(t *testing.T) {
	scriptParent := t.TempDir()
	vendoredDir := filepath.Join(scriptParent, "vendored")
	if err := os.MkdirAll(vendoredDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyScriptToDir(t, vendoredDir)
	writeSidecar(t, vendoredDir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	elsewhere := t.TempDir() // deliberately has no herdr-ewait.sh / sidecar of its own

	env := deadHookEnv(t)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + vendoredDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runRelative(t, elsewhere, "herdr-ewait.sh", []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (bare-name invocation from the wrong cwd must fail closed, never report 'this copy is the source'); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_BareNameFromWrongCwd(t *testing.T) {
	scriptParent := t.TempDir()
	vendoredDir := filepath.Join(scriptParent, "vendored")
	if err := os.MkdirAll(vendoredDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyScriptToDir(t, vendoredDir)
	writeSidecar(t, vendoredDir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	elsewhere := t.TempDir()

	env := deadHookEnv(t)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + vendoredDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runRelative(t, elsewhere, "herdr-ewait.sh", []string{"--sync", strings.Repeat("b", 40)}, env, 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d (bare-name invocation from the wrong cwd must fail closed); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

// --- strict, order-independent modifier/argument parsing ---

func TestCheckSource_Refuse_TypoModifier(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-vendroed"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (a typo'd modifier must be a usage error, not silently ignored); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// TestCheckSource_Refuse_ModifierValueLooksLikeFlag/TestSync_Refuse_ModifierValueLooksLikeFlag
// : a modifier value starting with '-' must be a usage
// error, never silently consumed as that modifier's value — otherwise
// `--expect-path --expect-vendored` would swallow the --expect-vendored FLAG
// as --expect-path's VALUE, silently disabling the --expect-vendored check
// the caller actually asked for (a false pass if the sidecar were also
// deleted, since --expect-vendored would never fire).
func TestCheckSource_Refuse_ModifierValueLooksLikeFlag(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	for _, args := range [][]string{
		{"--check-source", "--expect-path", "--expect-vendored"},
		{"--check-source", "--expect-repo", "--expect-vendored"},
		{"--check-source", "--file", "--expect-vendored"},
	} {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (a flag-shaped value must be refused, not swallowed); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

func TestSync_Refuse_ModifierValueLooksLikeFlag(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	sha := strings.Repeat("a", 40)

	for _, args := range [][]string{
		{"--sync", sha, "--expect-path", "--expect-repo"},
		{"--sync", sha, "--expect-repo", "--expect-path"},
	} {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (a flag-shaped value must be refused, not swallowed); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

// TestCheckSource_Refuse_RepeatedModifier/TestSync_Refuse_RepeatedModifier
// : a repeated modifier is a usage error, not last-wins.
func TestCheckSource_Refuse_RepeatedModifier(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	for _, args := range [][]string{
		{"--check-source", "--expect-repo", "a/b", "--expect-repo", "c/d"},
		{"--check-source", "--expect-path", "a/b.sh", "--expect-path", "c/d.sh"},
		{"--check-source", "--file", "/tmp/a.sh", "--file", "/tmp/b.sh"},
	} {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (a repeated modifier must be refused, not last-wins); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

func TestSync_Refuse_RepeatedModifier(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	sha := strings.Repeat("a", 40)

	for _, args := range [][]string{
		{"--sync", sha, "--expect-repo", "a/b", "--expect-repo", "c/d"},
		{"--sync", sha, "--expect-path", "a/b.sh", "--expect-path", "c/d.sh"},
	} {
		res := runEwaitScript(t, scriptPath, args, deadHookEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (a repeated modifier must be refused, not last-wins); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

func TestCheckSource_Refuse_ExtraPositionalArgument(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "bogus", "--expect-vendored"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (an extra positional argument must be a usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_ExtraArgumentAfterSha(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	// The second positional is ALSO a validly-shaped 40-hex sha (not "junk") —
	// a weaker version of this test using a non-sha-shaped stray argument would
	// pass "by accident" via a parser that just keeps the LAST positional seen
	// (overwriting the first) and lets cmd_sync's own sha-format check at the
	// bottom reject it instead of the arg parser's own extra-argument guard. Two
	// valid-looking shas force the parser's OWN guard to be what fires.
	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40), strings.Repeat("b", 40)}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (a stray trailing argument after the sha must be a usage error, even when it is itself sha-shaped); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- --expect-repo/--expect-path ---

func TestCheckSource_ExpectRepoPath(t *testing.T) {
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)

	newFixture := func(t *testing.T) (scriptPath, rawBase string) {
		t.Helper()
		dir := t.TempDir()
		scriptPath = copyScriptToDir(t, dir)
		scriptBytes, err := os.ReadFile(scriptPath)
		if err != nil {
			t.Fatal(err)
		}
		writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)
		rawBase = t.TempDir()
		writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)
		return scriptPath, rawBase
	}

	t.Run("expect-repo match", func(t *testing.T) {
		scriptPath, rawBase := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-repo", fakeRepo}, testHookEnv(t,
			"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
			"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		), 10*time.Second)
		if res.exitCode != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("expect-repo mismatch", func(t *testing.T) {
		scriptPath, _ := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-repo", "other-owner/other-repo"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceFail {
			t.Fatalf("exit = %d, want %d (a sidecar can only vouch for itself — --expect-repo mismatch must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
		}
		// A bare "expect-repo" substring check would be a false-positive-pass trap:
		// t.TempDir() embeds this subtest's own name ("expect-repo_mismatch") into
		// temp paths that show up in UNRELATED error messages (e.g. a failed-fetch
		// path), so anchor on the actual refusal message instead.
		if !strings.Contains(res.stderr, "--expect-repo: refused") {
			t.Errorf("stderr should contain the --expect-repo refusal message specifically, not some other failure; got %q", res.stderr)
		}
	})

	t.Run("expect-repo invalid value", func(t *testing.T) {
		scriptPath, _ := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-repo", "not a repo"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceFail {
			t.Fatalf("exit = %d, want %d (an invalid --expect-repo value must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
		}
		// "not a repo" also fails the (still-intact) mismatch check against the
		// real sidecar repo, which shares the same exit code — so an exit-code-only
		// assertion wouldn't distinguish a REMOVED format check from the mismatch
		// check still catching it. Anchor on the format-specific message.
		if !strings.Contains(res.stderr, "is not a valid owner/name") {
			t.Errorf("stderr should say the --expect-repo value itself is invalid, not merely mismatched; got %q", res.stderr)
		}
	})

	t.Run("expect-path match", func(t *testing.T) {
		scriptPath, rawBase := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-path", fakeScriptRelPath}, testHookEnv(t,
			"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
			"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		), 10*time.Second)
		if res.exitCode != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("expect-path mismatch", func(t *testing.T) {
		scriptPath, _ := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-path", "some/other/path.sh"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceFail {
			t.Fatalf("exit = %d, want %d (--expect-path mismatch must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
		}
		// Same false-positive-pass trap as above, for the "expect-path_mismatch"
		// subtest name.
		if !strings.Contains(res.stderr, "--expect-path: refused") {
			t.Errorf("stderr should contain the --expect-path refusal message specifically, not some other failure; got %q", res.stderr)
		}
	})

	t.Run("expect-path invalid value", func(t *testing.T) {
		scriptPath, _ := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-path", "/absolute/not/allowed"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceFail {
			t.Fatalf("exit = %d, want %d (an invalid --expect-path value must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "is not a valid path") {
			t.Errorf("stderr should say the --expect-path value itself is invalid, not merely mismatched; got %q", res.stderr)
		}
	})
}

func TestSync_ExpectRepoPath(t *testing.T) {
	newFixture := func(t *testing.T) (scriptPath, rawBase, remoteBase, headSHA string) {
		t.Helper()
		dir := t.TempDir()
		scriptPath = copyScriptToDir(t, dir)
		var oldSHA string
		remoteBase, oldSHA, headSHA = setupFakeRemote(t, fakeRepo)
		writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)
		newContent := fakeUpstreamScript(t, "expect-repo-path")
		rawBase = t.TempDir()
		writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)
		return scriptPath, rawBase, remoteBase, headSHA
	}

	t.Run("expect-repo match", func(t *testing.T) {
		scriptPath, rawBase, remoteBase, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-repo", fakeRepo}, testHookEnv(t,
			"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
			"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		), 10*time.Second)
		if res.exitCode != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("expect-repo mismatch", func(t *testing.T) {
		scriptPath, _, _, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-repo", "other-owner/other-repo"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitSyncBadDownload {
			t.Fatalf("exit = %d, want %d (--expect-repo mismatch must fail closed); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
		}
		// A bare "expect-repo" substring check would be a false-positive-pass trap:
		// t.TempDir() embeds this subtest's own name ("expect-repo_mismatch") into
		// temp paths that show up in UNRELATED error messages (e.g. a failed-fetch
		// path), so anchor on the actual refusal message instead.
		if !strings.Contains(res.stderr, "--expect-repo: refused") {
			t.Errorf("stderr should contain the --expect-repo refusal message specifically, not some other failure; got %q", res.stderr)
		}
	})

	t.Run("expect-repo invalid value", func(t *testing.T) {
		scriptPath, _, _, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-repo", "not a repo"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitSyncBadDownload {
			t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
		}
		// See the check-source equivalent: "not a repo" also fails the
		// (still-intact) mismatch check, which shares this exit code — anchor on
		// the format-specific message so a removed format check is actually caught.
		if !strings.Contains(res.stderr, "is not a valid owner/name") {
			t.Errorf("stderr should say the --expect-repo value itself is invalid, not merely mismatched; got %q", res.stderr)
		}
	})

	t.Run("expect-path match", func(t *testing.T) {
		scriptPath, rawBase, remoteBase, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-path", fakeScriptRelPath}, testHookEnv(t,
			"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
			"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		), 10*time.Second)
		if res.exitCode != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("expect-path mismatch", func(t *testing.T) {
		scriptPath, _, _, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-path", "some/other/path.sh"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitSyncBadDownload {
			t.Fatalf("exit = %d, want %d (--expect-path mismatch must fail closed); stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
		}
		// Same false-positive-pass trap as above, for the "expect-path_mismatch"
		// subtest name.
		if !strings.Contains(res.stderr, "--expect-path: refused") {
			t.Errorf("stderr should contain the --expect-path refusal message specifically, not some other failure; got %q", res.stderr)
		}
	})

	t.Run("expect-path invalid value", func(t *testing.T) {
		scriptPath, _, _, headSHA := newFixture(t)
		res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA, "--expect-path", "/absolute/not/allowed"}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitSyncBadDownload {
			t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "is not a valid path") {
			t.Errorf("stderr should say the --expect-path value itself is invalid, not merely mismatched; got %q", res.stderr)
		}
	})
}

// TestSync_ExpectRepoPath_OrderIndependent: the --expect-* modifiers may appear
// BEFORE the sha|main positional too (the strict parser accepts either order).
func TestSync_ExpectRepoPath_OrderIndependent(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)
	newContent := fakeUpstreamScript(t, "order-independent")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", "--expect-repo", fakeRepo, headSHA, "--expect-path", fakeScriptRelPath}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (modifiers before the sha positional must still parse); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- exit 14, PARTIALLY APPLIED ---

// writeFakeMvFailingForSidecar installs an `mv` that fails ONLY when one of its
// arguments mentions the sidecar's own name — letting the FIRST atomic replace
// (the script file) succeed via the real mv while the SECOND (the sidecar)
// fails, reproducing the exact window exit 14 exists for.
func writeFakeMvFailingForSidecar(t *testing.T, stubDir string) {
	t.Helper()
	realMv, err := exec.LookPath("mv")
	if err != nil {
		t.Skip("mv not found in PATH")
	}
	script := "#!/usr/bin/env bash\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in *herdr-ewait.source*) exit 1 ;; esac\n" +
		"done\n" +
		"exec '" + realMv + "' \"$@\"\n"
	writeExec(t, filepath.Join(stubDir, "mv"), script)
}

func TestSync_PartiallyApplied_ExitCode14(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, oldSHA, headSHA := setupFakeRemote(t, fakeRepo)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	newContent := fakeUpstreamScript(t, "partial-apply")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	stubDir := t.TempDir()
	writeFakeMvFailingForSidecar(t, stubDir)

	env := testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	res := runEwaitScript(t, scriptPath, []string{"--sync", headSHA}, env, 10*time.Second)

	if res.exitCode != exitSyncPartiallyApplied {
		t.Fatalf("exit = %d, want %d (PARTIALLY APPLIED, distinct from a clean refusal); stdout=%q stderr=%q", res.exitCode, exitSyncPartiallyApplied, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "PARTIALLY APPLIED") {
		t.Errorf("stderr should say PARTIALLY APPLIED; got %q", res.stderr)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Errorf("script file should have been replaced even though the sidecar mv failed; got %q", got)
	}
	sidecarData, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecarData), "sha="+oldSHA) {
		t.Errorf("sidecar should still say the OLD sha after a partial apply; got %q", sidecarData)
	}
}

// --- load_sidecar trim must be locale-stable, never silently skip a line ---

// availableUTF8Locale returns the first UTF-8 locale name `locale -a` lists
// (preferring en_US.UTF-8), or "" if none is installed on this machine.
func availableUTF8Locale(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("locale", "-a").Output()
	if err != nil {
		return ""
	}
	names := strings.Fields(string(out))
	preferred := []string{"en_US.UTF-8", "en_US.utf8", "C.UTF-8", "C.utf8"}
	for _, p := range preferred {
		for _, n := range names {
			if strings.EqualFold(n, p) {
				return n
			}
		}
	}
	for _, n := range names {
		if strings.Contains(strings.ToUpper(n), "UTF-8") || strings.Contains(strings.ToUpper(n), "UTF8") {
			return n
		}
	}
	return ""
}

// TestCheckSource_Refuse_SidecarInvalidUTF8Line: pins
// LANG/LC_ALL to a real UTF-8 locale in the CHILD's environment (not just
// relying on hermeticEnv's minimal env defaulting to the POSIX/C locale,
// which would never have exercised the original sed-under-UTF-8 bug at all)
// — load_sidecar's own `local LC_ALL=C` must still reject the invalid-byte
// line even though the ambient locale actively requests UTF-8.
func TestCheckSource_Refuse_SidecarInvalidUTF8Line(t *testing.T) {
	loc := availableUTF8Locale(t)
	if loc == "" {
		t.Skip("no UTF-8 locale installed on this machine")
	}

	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	var buf bytes.Buffer
	buf.WriteString("repo=" + fakeRepo + "\n")
	buf.WriteString("path=" + fakeScriptRelPath + "\n")
	buf.WriteString("sha=" + strings.Repeat("a", 40) + "\n")
	// A non-comment, non-key=value line containing invalid UTF-8 bytes: under a
	// UTF-8 locale a sed-based trim could choke on this and silently skip the
	// line instead of rejecting the sidecar — LC_ALL=C plus pure bash trimming
	// must reject it like any other unparseable line.
	buf.Write([]byte{0xff, 0xfe, ' ', 'n', 'o', 't', ' ', 'v', 'a', 'l', 'i', 'd', '\n'})
	if err := os.WriteFile(filepath.Join(dir, "herdr-ewait.source"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t, "LANG="+loc, "LC_ALL="+loc), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (an invalid-byte line must be rejected under a UTF-8 locale, not silently skipped); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "malformed") {
		t.Errorf("stderr should say the sidecar is malformed; got %q", res.stderr)
	}
}

// --- sha256_of must hash via stdin, never by filename argument ---

func TestCheckSource_Match_PathContainsBackslash(t *testing.T) {
	parent := t.TempDir()
	weirdDir := filepath.Join(parent, `weird\dir`)
	if err := os.MkdirAll(weirdDir, 0o755); err != nil {
		t.Skipf("could not create a directory with a backslash in its name on this filesystem: %v", err)
	}
	scriptPath := copyScriptToDir(t, weirdDir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, weirdDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	path := pathWithoutSha256sum(t)
	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, hermeticEnvCustomPath(t, path,
		"HERDR_EWAIT_TEST_HOOKS=1",
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (a backslash in the script's own path must not corrupt sha256 hashing via a filename-escaping hash tool); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a clean match; got %q", res.stdout)
	}
}

// --- CDPATH must never hijack resolution to a decoy directory ---

func TestCheckSource_CDPathDecoyDirectory_DoesNotHijackResolution(t *testing.T) {
	scriptParent := t.TempDir()
	const scriptSubdir = "vendored"
	realDir := filepath.Join(scriptParent, scriptSubdir)
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := copyScriptToDir(t, realDir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, realDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, scriptBytes)

	// A decoy parent directory, listed in CDPATH, that ALSO has a "vendored"
	// subdirectory — with a DIFFERENT sidecar naming a different repo. Confirmed
	// experimentally: bash's CDPATH search wins even when cwd ALREADY has a
	// matching subdirectory, so without `unset CDPATH` in script_self_path, `cd
	// vendored` would silently jump HERE instead of staying in scriptParent,
	// resolving check-source against the wrong repo/sidecar entirely (not merely
	// emitting a corrupted extra stdout line, as the plain CDPATH test above
	// already covers).
	decoyParent := t.TempDir()
	decoyDir := filepath.Join(decoyParent, scriptSubdir)
	if err := os.MkdirAll(decoyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyScriptToDir(t, decoyDir)
	const decoyRepo = "decoy-owner/decoy-repo"
	writeSidecar(t, decoyDir, decoyRepo, fakeScriptRelPath, strings.Repeat("d", 40))

	env := append(testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), "CDPATH="+decoyParent)

	res := runRelative(t, scriptParent, filepath.Join(scriptSubdir, "herdr-ewait.sh"), []string{"--check-source"}, env, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (CDPATH must not hijack resolution to the decoy directory); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a clean match against the REAL sidecar; got %q", res.stdout)
	}
	if strings.Contains(res.stdout, decoyRepo) || strings.Contains(res.stderr, decoyRepo) {
		t.Errorf("output mentions the decoy repo %q — CDPATH hijacked resolution to the wrong directory; stdout=%q stderr=%q", decoyRepo, res.stdout, res.stderr)
	}
}

// --- --check-source --file: check a GIVEN file/sidecar instead of $0, so a
// trusted copy can check an untrusted (e.g. a PR's) vendored copy without the
// check being able to vouch for itself ---

func TestCheckSource_File_Match(t *testing.T) {
	trustedDir := t.TempDir() // the "trusted" copy's own dir — no sidecar here, unused
	trustedScript := copyScriptToDir(t, trustedDir)

	targetDir := t.TempDir() // the "untrusted"/PR copy being checked
	targetScript := copyScriptToDir(t, targetDir)
	targetBytes, err := os.ReadFile(targetScript)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, targetBytes)

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", targetScript}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (match against the --file target, not the trusted copy's own $0); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "match") {
		t.Errorf("stdout should report a match; got %q", res.stdout)
	}
}

// TestCheckSource_File_TrustedMatchesPinned_TargetModified_Drift and
// TestCheckSource_File_TrustedModified_TargetMatchesPinned:
// every --file test above used a trusted copy byte-identical to the --file
// target, so a mutant that hashes $0 (the trusted copy) instead of $self (the
// --file target) survives unnoticed — the whole point of --file is to let a
// TRUSTED copy check an UNTRUSTED one, so the trusted and target bytes must
// differ to actually exercise which one gets hashed as "local".
func TestCheckSource_File_TrustedMatchesPinned_TargetModified_Drift(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir) // trusted copy == the real (pinned) bytes

	targetDir := t.TempDir()
	targetScript := copyScriptToDir(t, targetDir)
	tamperedTarget := fakeUpstreamScript(t, "tampered-target")
	if err := os.WriteFile(targetScript, tamperedTarget, 0o755); err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	// Pin content equals the TRUSTED copy's bytes (the real upstream source) —
	// the --file TARGET has silently drifted away from it.
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, realScriptBytes(t))

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", targetScript}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceDrift {
		t.Fatalf("exit = %d, want %d (DRIFT: the --file target, not the trusted copy, has diverged from the pin); stdout=%q stderr=%q", res.exitCode, exitCheckSourceDrift, res.stdout, res.stderr)
	}

	// The printed "local" hash must specifically be the --file TARGET's hash —
	// a mutant hashing $0 (the trusted copy, which equals the pin) instead of
	// $self would print the TRUSTED copy's hash here, which would equal the
	// pinned hash and wrongly report exit 0 "match" instead of DRIFT.
	wantLocalHash := sha256Hex(tamperedTarget)
	hashes := sha256HexPattern.FindAllString(res.stderr, -1)
	if len(hashes) < 1 {
		t.Fatalf("expected at least one sha256 hash printed on DRIFT; stderr=%q", res.stderr)
	}
	if hashes[0] != wantLocalHash {
		t.Errorf("printed local hash = %s, want the --file TARGET's hash %s (hashed the trusted copy's own $0 instead of --file's target?); stderr=%q", hashes[0], wantLocalHash, res.stderr)
	}
}

func TestCheckSource_File_TrustedModified_TargetMatchesPinned(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)
	// Modify the TRUSTED copy itself — the match/drift decision must depend
	// only on the --file TARGET, never on the trusted copy's own bytes.
	modifiedTrusted := fakeUpstreamScript(t, "trusted-itself-modified")
	if err := os.WriteFile(trustedScript, modifiedTrusted, 0o755); err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	targetScript := copyScriptToDir(t, targetDir) // target == the real (pinned) bytes
	targetBytes, err := os.ReadFile(targetScript)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, targetBytes)

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", targetScript}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (the --file TARGET matches the pin even though the trusted copy's own bytes differ from it); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_File_Drift(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)

	targetDir := t.TempDir()
	targetScript := copyScriptToDir(t, targetDir)

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	// The pinned content differs from the target file's actual bytes — a real
	// drift, e.g. the PR edited the vendored copy without updating the sidecar.
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\necho different\n"))

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", targetScript}, testHookEnv(t,
		"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
	), 10*time.Second)

	if res.exitCode != exitCheckSourceDrift {
		t.Fatalf("exit = %d, want %d (DRIFT against the --file target); stdout=%q stderr=%q", res.exitCode, exitCheckSourceDrift, res.stdout, res.stderr)
	}
}

func TestCheckSource_File_Refuse_SymlinkedTarget(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)

	targetDir := t.TempDir()
	realPath := filepath.Join(targetDir, "real-herdr-ewait.sh")
	if err := os.WriteFile(realPath, realScriptBytes(t), 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(targetDir, "herdr-ewait.sh")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", linkPath}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (a symlinked --file target must refuse, same rule as $0); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	// A bare "symlink" substring check is a false-positive-pass trap here too:
	// this test's own name ("...SymlinkedTarget") is embedded by t.TempDir()
	// into deadHookEnv's "unreachable" path, and lowercasing "Symlinked"
	// produces "symlink" — so a bypassed guard falling through to the
	// ancestry-check failure message would still spuriously satisfy a bare
	// substring check. Anchor on the exact refusal message instead.
	if !strings.Contains(res.stderr, "is a symlink; check-source must run against the real file, not a symlink") {
		t.Errorf("stderr should contain the specific symlink-refusal message; got %q", res.stderr)
	}
}

func TestCheckSource_File_ExpectVendored_NoSidecar(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)

	targetDir := t.TempDir() // no sidecar written — this would-be target "is the source"
	targetScript := copyScriptToDir(t, targetDir)

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", targetScript, "--expect-vendored"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceExpectVendored {
		t.Fatalf("exit = %d, want %d (--file target has no sidecar, --expect-vendored must refuse); stdout=%q stderr=%q", res.exitCode, exitCheckSourceExpectVendored, res.stdout, res.stderr)
	}
}

func TestCheckSource_File_Refuse_NonexistentPath(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)

	res := runEwaitScript(t, trustedScript, []string{"--check-source", "--file", filepath.Join(t.TempDir(), "nope.sh")}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (a nonexistent --file target must fail closed); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
}

// TestCheckSource_Refuse_FileAsLastArg/TestCheckSource_Refuse_FileEmptyValue
// : --file with no value at all (it's the last argument) or
// an explicit empty-string value must be a usage error, not silently treated
// as "no --file given" (which would fall back to checking $0 instead of
// failing the caller's request closed).
func TestCheckSource_Refuse_FileAsLastArg(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--file"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (--file with no value must be a usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_Refuse_FileEmptyValue(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--file", ""}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (--file \"\" must be a usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestCheckSource_File_CombinedWithExpectRepoPath(t *testing.T) {
	trustedDir := t.TempDir()
	trustedScript := copyScriptToDir(t, trustedDir)

	targetDir := t.TempDir()
	targetScript := copyScriptToDir(t, targetDir)
	targetBytes, err := os.ReadFile(targetScript)
	if err != nil {
		t.Fatal(err)
	}

	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, targetDir, fakeRepo, fakeScriptRelPath, headSHA)
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, targetBytes)

	t.Run("match", func(t *testing.T) {
		res := runEwaitScript(t, trustedScript, []string{
			"--check-source", "--file", targetScript,
			"--expect-repo", fakeRepo, "--expect-path", fakeScriptRelPath,
		}, testHookEnv(t,
			"HERDR_EWAIT_RAW_BASE_URL="+rawBaseURL(rawBase),
			"HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase,
		), 10*time.Second)
		if res.exitCode != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		res := runEwaitScript(t, trustedScript, []string{
			"--check-source", "--file", targetScript,
			"--expect-repo", "other-owner/other-repo",
		}, deadHookEnv(t), 10*time.Second)
		if res.exitCode != exitCheckSourceFail {
			t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "--expect-repo: refused") {
			t.Errorf("stderr should contain the --expect-repo refusal message; got %q", res.stderr)
		}
	})
}
