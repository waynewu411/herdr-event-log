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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var sha256HexPattern = regexp.MustCompile(`[0-9a-f]{64}`)

const (
	exitCheckSourceDrift         = 7
	exitCheckSourceFail          = 8
	exitCheckSourceUpstreamNewer = 9
	exitSyncNoSidecar            = 10
	exitSyncOnDefaultBranch      = 11
	exitSyncBadDownload          = 12
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

func hermeticEnvCustomPath(t *testing.T, path string, extra ...string) []string {
	t.Helper()
	env := []string{"PATH=" + path}
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

// --- --check-source ---

func TestCheckSource_NoSidecar_IsSource(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, hermeticEnv(t), 10*time.Second)

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
	}{
		{"gate off: overrides ignored, real hosts targeted", false, "raw.githubusercontent.com", "github.com"},
		{"gate on: local overrides honoured", true, "RAW_MARKER_XYZ", "REMOTE_MARKER_XYZ"},
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

			hasWarning := strings.Contains(res.stderr, "WARNING: test override active")
			if tc.setGate && !hasWarning {
				t.Errorf("stderr should warn when a test override is active; got %q", res.stderr)
			}
			if !tc.setGate && hasWarning {
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

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, linkPath, []string{"--sync", strings.Repeat("b", 40)}, hermeticEnv(t), 10*time.Second)

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

	res := runEwaitScript(t, scriptPath, []string{"--sync", "not-a-sha-or-main"}, hermeticEnv(t), 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_NoArg(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync"}, hermeticEnv(t), 10*time.Second)

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
		res := runEwaitScript(t, scriptPath, args, hermeticEnv(t), 10*time.Second)
		if res.exitCode != 4 {
			t.Errorf("args %v: exit = %d, want 4 (usage error); stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
	}
}

func TestSync_Refuse_InvalidSidecarFields(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, "../not/a/repo", fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, hermeticEnv(t), 10*time.Second)

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
