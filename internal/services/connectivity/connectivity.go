package connectivity

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const MihomoBin = "/usr/local/bin/mihomo"
const LegacySingBoxBin = "/usr/local/bin/sing-box"
const KernelTmp = "/opt/subgo/mihomo-install"

// moveFile moves a file, falling back to copy-on-cross-device.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// cross-device fallback
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(df, sf); err != nil {
		df.Close()
		return err
	}
	df.Close()
	os.Remove(src)
	return nil
}

// copyFile copies a file with the requested mode.
func copyFile(src, dst string, mode os.FileMode) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(df, sf); err != nil {
		df.Close()
		return err
	}
	return df.Close()
}

type KernelStatus struct {
	OK        bool   `json:"ok"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Kernel    string `json:"kernel"`
	Extra     any    `json:"extra,omitempty"`
}

func (s *Service) KernelStatus() KernelStatus {
	st := KernelStatus{OK: true, Path: MihomoBin, Mode: "mihomo+proxy", Kernel: "mihomo"}
	if _, err := os.Stat(MihomoBin); err == nil {
		st.Installed = true
		out, _ := exec.Command(MihomoBin, "-v").CombinedOutput()
		st.Version = strings.TrimSpace(string(out))
	}
	return st
}
func (s *Service) InstallKernel() (string, error) {
	// Prefer an already staged Mihomo binary. This keeps install deterministic on
	// hosts where we manually provide a compatible build.
	for _, cand := range []string{"/tmp/mihomo-home-compatible", "/tmp/mihomo-home-runner"} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			if err := os.MkdirAll(KernelTmp, 0755); err != nil {
				return "", err
			}
			tmp := filepath.Join(KernelTmp, "mihomo.new")
			if err := copyFile(cand, tmp, 0755); err != nil {
				return "", err
			}
			if err := moveFile(tmp, MihomoBin); err != nil {
				return "", err
			}
			_ = os.Chmod(MihomoBin, 0755)
			out, err := exec.Command(MihomoBin, "-v").CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("verify failed: %s", strings.TrimSpace(string(out)))
			}
			return strings.TrimSpace(string(out)), nil
		}
	}

	if runtime.GOOS != "linux" {
		return "", errors.New("auto install currently supports linux")
	}
	arch := runtime.GOARCH
	assetNeedle := "linux-" + arch
	if arch == "amd64" {
		assetNeedle = "linux-amd64-compatible"
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", nil)
	req.Header.Set("User-Agent", "subgo")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch release HTTP %d", resp.StatusCode)
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	var assetURL string
	for _, a := range rel.Assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "mihomo") && strings.Contains(n, assetNeedle) && (strings.HasSuffix(n, ".gz") || strings.HasSuffix(n, ".tar.gz")) && !strings.Contains(n, "android") {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return "", fmt.Errorf("no mihomo %s gz asset found", assetNeedle)
	}
	r, err := http.Get(assetURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return "", fmt.Errorf("download HTTP %d", r.StatusCode)
	}
	if err := os.MkdirAll(KernelTmp, 0755); err != nil {
		return "", err
	}
	tmp := filepath.Join(KernelTmp, "mihomo.new")
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, gz); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	if err := moveFile(tmp, MihomoBin); err != nil {
		return "", err
	}
	_ = os.Chmod(MihomoBin, 0755)
	out, err := exec.Command(MihomoBin, "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("verify failed: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
func (s *Service) UninstallKernel() error {
	if _, err := os.Stat(MihomoBin); err == nil {
		return os.Remove(MihomoBin)
	}
	return nil
}
