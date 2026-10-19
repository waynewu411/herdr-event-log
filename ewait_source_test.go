package main

// TestCheckSource_*/TestSync_* exercise the vendoring commands added to
// scripts/herdr-ewait.sh by issue #13: --check-source [--latest] and --sync
// <sha|main>. Unlike ewait_test.go/ewait_resolution_test.go, these never
// start the fake herdr stub (both commands are herdr-free by design) and
// instead run against a throwaway COPY of the script, since --sync rewrites
// the script file in place. Network access is replaced by two test-only env
// overrides the script itself documents: HERDR_EWAIT_RAW_BASE_URL (raw
// content fetch) and HERDR_EWAIT_REMOTE_BASE_URL (the remote used to resolve
// "main"/HEAD). Both point at local fixtures (a plain directory tree served
// via file://, and a local bare git repo) so no test ever touches the
// network.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// copyScriptToDir copies the real scripts/herdr-ewait.sh into destDir so a
// test can let --sync mutate it without touching the repo's own copy.
func copyScriptToDir(t *testing.T, destDir string) string {
	t.Helper()
	src := ewaitScriptPath(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dest := filepath.Join(destDir, "herdr-ewait.sh")
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", dest, err)
	}
	return dest
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
// commit shas.
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

// --- subprocess runner (no herdr stub: --check-source/--sync never call herdr) ---

func runEwaitScript(t *testing.T, scriptPath string, args []string, extraEnv []string, timeout time.Duration) ewaitResult {
	t.Helper()
	return startEwaitAt(t, scriptPath, args, extraEnv).wait(t, timeout)
}

func startEwaitAt(t *testing.T, scriptPath string, args []string, extraEnv []string) *ewaitProcess {
	t.Helper()
	requireEwaitTools(t)
	cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
	cmd.Env = append(os.Environ(), extraEnv...)
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

	res := runEwaitScript(t, scriptPath, []string{"--check-source"}, nil, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(strings.ToLower(res.stdout), "source") {
		t.Errorf("stdout should say this copy is the source; got %q", res.stdout)
	}
}

func TestCheckSource_Match(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	sha := strings.Repeat("a", 40)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, sha)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, sha, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source"},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

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

	sha := strings.Repeat("b", 40)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, sha)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, sha, fakeScriptRelPath, []byte("#!/usr/bin/env bash\necho different\n"))

	res := runEwaitScript(t, scriptPath, []string{"--check-source"},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

	if res.exitCode != exitCheckSourceDrift {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceDrift, res.stdout, res.stderr)
	}
	// Both hashes must be printed (local sha256 vs the pinned/upstream one).
	if strings.Count(res.stderr, "sha256") < 1 {
		t.Errorf("stderr should mention sha256 hashes on drift; got %q", res.stderr)
	}
}

func TestCheckSource_FetchFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)

	sha := strings.Repeat("c", 40)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, sha)

	// rawBase exists but has no fixture file at all under it -> curl fails closed.
	rawBase := t.TempDir()

	res := runEwaitScript(t, scriptPath, []string{"--check-source"},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

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
		{"path traversal", fakeRepo, "scripts/../../../etc/passwd", strings.Repeat("a", 40)},
		{"leading slash path", fakeRepo, "/etc/passwd", strings.Repeat("a", 40)},
		{"bad sha length", fakeRepo, fakeScriptRelPath, "abc123"},
		{"bad sha charset", fakeRepo, fakeScriptRelPath, strings.Repeat("g", 40)},
		{"uppercase sha", fakeRepo, fakeScriptRelPath, strings.Repeat("A", 40)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scriptPath := copyScriptToDir(t, dir)
			writeSidecar(t, dir, tc.repo, tc.path, tc.sha)

			// Deliberately no HERDR_EWAIT_RAW_BASE_URL fixture for these
			// values at all: validation must reject before ever building a
			// fetch URL from attacker-controlled sidecar fields.
			res := runEwaitScript(t, scriptPath, []string{"--check-source"}, nil, 10*time.Second)

			if res.exitCode != exitCheckSourceFail {
				t.Fatalf("exit = %d, want %d (invalid sidecar); stdout=%q stderr=%q", res.exitCode, exitCheckSourceFail, res.stdout, res.stderr)
			}
			if !strings.Contains(strings.ToLower(res.stderr), "invalid") {
				t.Errorf("stderr should say the sidecar is invalid; got %q", res.stderr)
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

	remoteBase, oldSHA, _ := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, oldSHA, fakeScriptRelPath, scriptBytes)

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, []string{
		"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL=" + remoteBase,
	}, 10*time.Second)

	if res.exitCode != exitCheckSourceUpstreamNewer {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitCheckSourceUpstreamNewer, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, oldSHA[:7]) {
		t.Errorf("stderr should mention the pinned sha; got %q", res.stderr)
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

	res := runEwaitScript(t, scriptPath, []string{"--check-source", "--latest"}, []string{
		"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL=" + remoteBase,
	}, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- --sync ---

func TestSync_Success_ExplicitSHA(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	if err := os.Chmod(scriptPath, 0o744); err != nil {
		t.Fatal(err)
	}

	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("d", 40)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	newContent := []byte("#!/usr/bin/env bash\necho synced-explicit\n")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, newSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", newSHA},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, oldSHA) || !strings.Contains(res.stdout, newSHA) {
		t.Errorf("stdout should print old and new sha; got %q", res.stdout)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newContent) {
		t.Errorf("script file not replaced; got %q", got)
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
	if !strings.Contains(string(sidecarData), "sha="+newSHA) {
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

	newContent := []byte("#!/usr/bin/env bash\necho synced-main\n")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, headSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", "main"}, []string{
		"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase),
		"HERDR_EWAIT_REMOTE_BASE_URL=" + remoteBase,
	}, 10*time.Second)

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

	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("e", 40)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, oldSHA)

	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
	gitCmd(t, dir, "checkout", "-q", "-b", "feature/sync-test")

	newContent := []byte("#!/usr/bin/env bash\necho synced-feature-branch\n")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, newSHA, fakeScriptRelPath, newContent)

	res := runEwaitScript(t, scriptPath, []string{"--sync", newSHA},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (non-default branch must be allowed); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_NoSidecar(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("a", 40)}, nil, 10*time.Second)

	if res.exitCode != exitSyncNoSidecar {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncNoSidecar, res.stdout, res.stderr)
	}
	after, _ := os.ReadFile(scriptPath)
	if string(before) != string(after) {
		t.Errorf("script file must not be touched on refusal")
	}
}

func TestSync_Refuse_OnDefaultBranch(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, nil, 10*time.Second)

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

	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
	headSHA := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	gitCmd(t, dir, "checkout", "-q", headSHA)

	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, nil, 10*time.Second)

	if res.exitCode != exitSyncOnDefaultBranch {
		t.Fatalf("exit = %d, want %d (detached HEAD must refuse); stdout=%q stderr=%q", res.exitCode, exitSyncOnDefaultBranch, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_BadDownload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	before, _ := os.ReadFile(scriptPath)
	sidecarPath := writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))
	sidecarBefore, _ := os.ReadFile(sidecarPath)

	newSHA := strings.Repeat("f", 40)
	rawBase := t.TempDir()
	// Syntactically invalid bash -> must fail `bash -n` and never be installed.
	writeRawFixture(t, rawBase, fakeRepo, newSHA, fakeScriptRelPath, []byte("#!/usr/bin/env bash\nif true; then\necho unterminated\n"))

	res := runEwaitScript(t, scriptPath, []string{"--sync", newSHA},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

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

func TestSync_Refuse_DownloadFailure(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	rawBase := t.TempDir() // nothing under it -> curl fails
	res := runEwaitScript(t, scriptPath, []string{"--sync", strings.Repeat("f", 40)},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)

	if res.exitCode != exitSyncBadDownload {
		t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", res.exitCode, exitSyncBadDownload, res.stdout, res.stderr)
	}
}

func TestSync_Refuse_BadArgFormat(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	res := runEwaitScript(t, scriptPath, []string{"--sync", "not-a-sha-or-main"}, nil, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit = %d, want 4 (usage error); stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
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
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	newSHA := strings.Repeat("f", 40)
	newContent := []byte("#!/usr/bin/env bash\necho synced-while-running\n")
	rawBase := t.TempDir()
	writeRawFixture(t, rawBase, fakeRepo, newSHA, fakeScriptRelPath, newContent)

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

	syncRes := runEwaitScript(t, scriptPath, []string{"--sync", newSHA},
		[]string{"HERDR_EWAIT_RAW_BASE_URL=" + rawBaseURL(rawBase)}, 10*time.Second)
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

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 2 {
		t.Fatalf("running instance exit = %d, want 2 (overall timeout) — the in-flight process must keep running against its original inode; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
}
