package main

// TestCheckSource_*/TestSync_* exercise the vendoring commands added to
// scripts/herdr-ewait.sh by issue #13 (hardened per a round-1 adversarial
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
// herdr-ewait.sh-shaped content (so it passes --sync's M1 content checks:
// non-empty, correct shebang, the SIDECAR_NAME sentinel, and a working
// --help) but distinguishable from the real file via a trailing marker
// comment, so a hash comparison correctly reports a difference.
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
// commit, and records refs/remotes/origin/HEAD locally (a pure local ref
// write — no real 'origin' remote is needed) so default_branch_of() can
// resolve the default branch name without any network access, exactly as a
// real clone or `git remote set-head origin -a` would leave it.
func initGitRepoWithDefaultBranch(t *testing.T, dir string) {
	t.Helper()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init", "--allow-empty")
	gitCmd(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/main")
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeFakeGit/writeFakeCurl install a fully-fabricated git/curl on stubDir:
// they log their arguments to logPath and exit 0 (git) / 1 (curl) — used
// only to prove WHICH base URL a call targeted (the test-hook gate, M2)
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
// empty-hash-output fail-closed guard (L5).
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
func hermeticEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
		// Belt-and-suspenders on top of the script's own git_safe scrubbing: never
		// let a global/system gitconfig on the test machine influence a git call.
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	}
	if home := os.Getenv("HOME"); home != "" {
		env = append(env, "HOME="+home)
	}
	return append(env, extra...)
}

func testHookEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return hermeticEnv(t, append([]string{"HERDR_EWAIT_TEST_HOOKS=1"}, extra...)...)
}

// deadHookEnv is hermeticEnv with the test-hook env vars pointed at an inert,
// nonexistent local file:// path — defense-in-depth (L6) for refusal-path tests
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
// Used by the L3 (sha256_of-via-stdin) regression test so it reproduces the
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
	// upstream-newer (M4): a commit-only move with unchanged content is exit 0.
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
	// FILE did not change — must be exit 0, not upstream-newer (M4).
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

	env := []string{
		"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
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
}

func TestCheckSource_TestHookRejectsUserinfoHost(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	stubDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls.log")
	writeFakeGit(t, stubDir, logPath) // ancestry must "pass" to reach raw-base resolution

	env := []string{
		"PATH=" + stubDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR=" + t.TempDir(),
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

// --- H1: self-path resolution hardening ---

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

	res := runEwaitScript(t, linkPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (symlinked check-source must refuse, same rule as --sync); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stderr), "symlink") {
		t.Errorf("stderr should mention the symlink; got %q", res.stderr)
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

// --- M1: default-branch refusal / git_safe hardening ---

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

// --- M2: static-only content checks (bash "$f" --help removed) ---

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
	// but if this were ever EXECUTED it would write a proof file — confirming M2's
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
		t.Fatalf("downloaded content was EXECUTED (proof file exists) — M2 regression")
	}
}

func TestSync_Refuse_BashNGate_WithBothSentinelsPresent(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// Isolates the bash -n gate specifically: both M1 sentinels are present (so
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

// --- L4: --latest sub-failures, each distinctly ---

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
	if !strings.Contains(strings.ToLower(res.stderr), "symlink") {
		t.Errorf("stderr should mention the symlink; got %q", res.stderr)
	}
}

func TestSync_Refuse_GitMissingButInGitDir(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := hermeticEnvCustomPath(t, pathWithoutGit(t))
	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, env, 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (git missing but inside a work tree must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
}

func TestSync_GitMissingNoRepo_SkipsBranchRefusal(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	env := hermeticEnvCustomPath(t, pathWithoutGit(t))
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

func TestSync_Refuse_MissingShebang(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, []byte("echo hi\n"))

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

// --- Round-4 review: M1 (bare-name $0 resolution), M2 (strict arg parsing),
// M3 (--expect-repo/--expect-path), L1 (exit 14), L2 (sidecar trim locale), L3
// (hash-by-stdin), L6 (CDPATH decoy + dead hook bases for refusal tests) ---

// TestCheckSource_Refuse_BareNameFromWrongCwd/TestSync_Refuse_BareNameFromWrongCwd
// (M1): bash resolves a bare (no "/") script-file argument to `bash <name>` via a
// PATH search — confirmed experimentally — but leaves $0 as the bare name, NOT the
// resolved path. Without the M1 fix, script_self_path would resolve
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

// --- M2: strict, order-independent modifier/argument parsing ---

func TestCheckSource_Refuse_TypoModifier(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--expect-vendroed"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (a typo'd modifier must be a usage error, not silently ignored); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
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

// --- M3: --expect-repo/--expect-path ---

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
// BEFORE the sha|main positional too (M2's strict parser accepts either order).
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

// --- L1: exit 14, PARTIALLY APPLIED ---

// writeFakeMvFailingForSidecar installs an `mv` that fails ONLY when one of its
// arguments mentions the sidecar's own name — letting the FIRST atomic replace
// (the script file) succeed via the real mv while the SECOND (the sidecar)
// fails, reproducing the exact window L1's exit 14 exists for.
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

// --- L2: load_sidecar trim must be locale-stable, never silently skip a line ---

func TestCheckSource_Refuse_SidecarInvalidUTF8Line(t *testing.T) {
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

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, deadHookEnv(t), 10*time.Second)

	if res.exitCode != exitCheckSourceFail {
		t.Fatalf("exit = %d, want %d (an invalid-byte line must be rejected, not silently skipped); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "malformed") {
		t.Errorf("stderr should say the sidecar is malformed; got %q", res.stderr)
	}
}

// --- L3: sha256_of must hash via stdin, never by filename argument ---

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

// --- L6: CDPATH must never hijack resolution to a decoy directory ---

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
