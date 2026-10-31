package connectivity

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Spittingjiu/subgo/internal/subconv"
	"gopkg.in/yaml.v3"
)

const checkTargetURL = "https://www.gstatic.com/generate_204"

// Options are private test seams, not user-facing configuration. Production
// always uses the fixed HTTPS target and system roots. Tests replace commands
// with the Go helper subprocess and use loopback-only TLS/HTTP fixtures.
type mihomoExecutor struct {
	bin            string
	commandContext func(context.Context, string, ...string) *exec.Cmd
	checkTimeout   time.Duration
	runTimeout     time.Duration
	readyTimeout   time.Duration
	pollInterval   time.Duration
	probeTimeout   time.Duration
	targetURL      string
	roots          *x509.CertPool
}

func newMihomoExecutor() *mihomoExecutor {
	return &mihomoExecutor{
		bin: MihomoBin, commandContext: exec.CommandContext,
		checkTimeout: 5 * time.Second, runTimeout: 15 * time.Second,
		readyTimeout: 2500 * time.Millisecond, pollInterval: 50 * time.Millisecond,
		probeTimeout: 8 * time.Second, targetURL: checkTargetURL,
	}
}

func (e *mihomoExecutor) Check(ctx context.Context, t Target) (r Result) {
	started := time.Now()
	defer func() {
		if recover() != nil {
			r = resultFor(CodeExecutorError)
		}
		r.NodeID, r.NodeHash, r.LinkVersion = t.ID, t.NodeHash, t.LinkVersion
		r.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.ElapsedMS = time.Since(started).Milliseconds()
	}()
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	st, err := os.Stat(e.bin)
	if err != nil || st.IsDir() || st.Mode()&0111 == 0 {
		return resultFor(CodeKernelMissing)
	}
	proxy := subconv.ClashProxy(t.RawLink)
	if proxy == nil {
		return resultFor(CodeUnsupportedLink)
	}
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	dir, err := os.MkdirTemp("", "subgo-mihomo-") // mode 0700
	if err != nil {
		return resultFor(CodeTempDir)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil && ctx.Err() == nil {
			r = resultFor(CodeTempCleanup)
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return resultFor(CodePortUnavailable)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return resultFor(CodePortUnavailable)
	}
	// A private, random proxy password prevents a raced/reused local port
	// from accidentally proving the wrong proxy. It stays in the 0600 config.
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return resultFor(CodeConfigWrite)
	}
	password := base64.RawURLEncoding.EncodeToString(random[:])
	cfg := mihomoCheckConfig(proxy, port, password)
	cfgYAML, err := yaml.Marshal(cfg)
	if err != nil {
		return resultFor(CodeConfigInvalid)
	}
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, cfgYAML, 0600); err != nil {
		return resultFor(CodeConfigWrite)
	}

	// Official os/exec: Run owns Start+Wait; context cancellation kills the
	// validation child and Run still reaps it. Output is discarded, not parsed.
	checkCtx, checkCancel := context.WithTimeout(ctx, e.checkTimeout)
	checkCmd := e.commandContext(checkCtx, e.bin, "-d", dir, "-t", "-f", cfgPath)
	prepareCheckCommand(checkCmd, dir)
	err = checkCmd.Run()
	checkExpired := checkCtx.Err()
	checkCancel()
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	if checkExpired != nil {
		return resultFor(CodeConfigTimeout)
	}
	if err != nil {
		return resultFor(CodeConfigInvalid)
	}

	runCtx, runCancel := context.WithTimeout(ctx, e.runTimeout)
	defer runCancel()
	processCtx, processCancel := context.WithCancel(runCtx)
	defer processCancel()
	cmd := e.commandContext(runCtx, e.bin, "-d", dir, "-f", cfgPath)
	prepareCheckCommand(cmd, dir)
	child, err := startCheckChild(cmd, processCancel)
	if err != nil {
		if ctx.Err() != nil {
			return cancelledResult(ctx)
		}
		return resultFor(CodeKernelStart)
	}
	// Every successful Start has one Wait owner. All return paths Kill and
	// collect that Wait before deleting config, returning or releasing guard.
	defer func() {
		runCancel()
		child.stop()
	}()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	readyCtx, readyCancel := context.WithTimeout(processCtx, e.readyTimeout)
	err = waitForProxy(readyCtx, addr, child.done, e.pollInterval)
	readyCancel()
	if err != nil {
		return processFailure(ctx, runCtx, child, CodeProxyNotReady)
	}
	probeCtx, probeCancel := context.WithTimeout(processCtx, e.probeTimeout)
	defer probeCancel()
	proxyURL := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword("subgo-check", password)}
	r = testProxyContext(probeCtx, proxyURL, e.targetURL, e.roots)
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	if runCtx.Err() != nil {
		return resultFor(CodeKernelTimeout)
	}
	select {
	case <-child.done:
		return resultFor(CodeKernelExited)
	default:
	}
	return r
}

// Official Mihomo docs: global requires a GLOBAL selection and ignores rules.
// Rule mode with a single MATCH group forces this one node, with no DIRECT
// fallback, persisted selection, external controller, or production home/cache.
func mihomoCheckConfig(proxy map[string]any, port int, password string) map[string]any {
	proxy["name"] = "SUBGO_CHECK_NODE"
	return map[string]any{
		"mixed-port": port, "allow-lan": false, "bind-address": "127.0.0.1",
		"mode": "rule", "log-level": "silent",
		"authentication": []string{"subgo-check:" + password}, "skip-auth-prefixes": []string{},
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"proxies": []map[string]any{proxy},
		"proxy-groups": []map[string]any{
			{"name": "SUBGO_CHECK", "type": "select", "proxies": []string{"SUBGO_CHECK_NODE"}},
		},
		"rules": []string{"MATCH,SUBGO_CHECK"},
	}
}

func prepareCheckCommand(cmd *exec.Cmd, dir string) {
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	// Official Mihomo CLI permits config/controller/script overrides via
	// CLASH_* env. A check must not inherit another instance's configuration
	// or post-up/post-down scripts. This only changes the child environment.
	env := cmd.Environ()
	clean := make([]string, 0, len(env))
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "CLASH_") {
			clean = append(clean, value)
		}
	}
	cmd.Env = clean
}

type checkChild struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startCheckChild(cmd *exec.Cmd, exited context.CancelFunc) (*checkChild, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	child := &checkChild{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait() // the sole Wait call, including natural exit/cancellation
		close(child.done)
		exited()
	}()
	return child, nil
}

func (child *checkChild) stop() {
	_ = child.cmd.Process.Kill()
	<-child.done // collect exactly one Wait; no orphan/zombie on return
}

func processFailure(ctx, runCtx context.Context, child *checkChild, fallback string) Result {
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	if runCtx.Err() != nil {
		return resultFor(CodeKernelTimeout)
	}
	select {
	case <-child.done:
		return resultFor(CodeKernelExited)
	default:
	}
	return resultFor(fallback)
}

func waitForProxy(ctx context.Context, addr string, processDone <-chan struct{}, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-processDone:
			return errors.New("check process exited")
		default:
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-processDone:
			return errors.New("check process exited")
		case <-ticker.C:
		}
	}
}

var (
	errProxyAuth   = errors.New("local proxy authentication failed")
	errProxyTunnel = errors.New("remote proxy tunnel failed")
	errProxyStatus = errors.New("local proxy rejected check")
)

// testProxyContext validates the target with system roots (or explicit local
// test roots), rejects redirects and accepts only an exact HTTPS 204 response.
// No request/transport error strings or response bodies are published.
func testProxyContext(ctx context.Context, proxyURL *url.URL, targetURL string, roots *x509.CertPool) Result {
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	target, err := url.Parse(targetURL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil ||
		target.Path != "/generate_204" || target.RawQuery != "" || target.Fragment != "" {
		return resultFor(CodeTargetInvalid)
	}
	if proxyURL == nil || proxyURL.Scheme != "http" {
		return resultFor(CodeProxyUnavailable)
	}
	host, port, err := net.SplitHostPort(proxyURL.Host)
	ip := net.ParseIP(host)
	portNum, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || portNum <= 0 || portNum > 65535 {
		return resultFor(CodeProxyUnavailable)
	}
	var connected atomic.Bool
	dialer := &net.Dialer{Timeout: time.Second}
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				connected.Store(true)
			}
			return conn, err
		},
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
			switch {
			case resp.StatusCode == http.StatusOK:
				return nil
			case resp.StatusCode == http.StatusProxyAuthRequired:
				return errProxyAuth
			case resp.StatusCode >= 500:
				return errProxyTunnel
			default:
				return errProxyStatus
			}
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return resultFor(CodeTargetInvalid)
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return cancelledResult(ctx)
		}
		if isTargetTLSError(err) {
			return resultFor(CodeTargetTLS)
		}
		if errors.Is(err, errProxyAuth) {
			return resultFor(CodeProxyAuth)
		}
		if errors.Is(err, errProxyStatus) || !connected.Load() {
			return resultFor(CodeProxyUnavailable)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return resultFor(CodeRemoteTimeout)
		}
		return resultFor(CodeRemoteError)
	}
	resp.Body.Close()
	if ctx.Err() != nil {
		return cancelledResult(ctx)
	}
	if resp.StatusCode != http.StatusNoContent {
		return resultFor(CodeTargetStatus)
	}
	r := resultFor(CodeOK)
	r.LatencyMS = &latency
	return r
}

func isTargetTLSError(err error) bool {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	return errors.Is(err, http.ErrSchemeMismatch) || errors.As(err, &verification) || errors.As(err, &authority) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &record) || errors.As(err, &alert)
}
