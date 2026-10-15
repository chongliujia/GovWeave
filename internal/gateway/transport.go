package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"govweave/internal/config"
)

func NormalizeUpstreamURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.User != nil || strings.ContainsAny(value, "?#\\") || u.RawPath != "" {
		return "", errors.New("上游地址无效，不能包含凭证、查询参数或片段")
	}
	origin, err := config.NormalizeURL(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", errors.New("上游地址须为有效的 HTTP(S) 地址")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !allowedIP(ip) {
		return "", errors.New("不能连接链路本地、组播或未指定地址")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return "", errors.New("上游路径不能包含 . 或 ..")
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~", c)) {
				return "", errors.New("上游路径包含不支持的字符")
			}
		}
	}
	return origin + strings.TrimRight(u.Path, "/"), nil
}

func allowedIP(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.Equal(net.IPv4bcast)
}

func guardedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid upstream host")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("upstream DNS lookup failed")
	}
	for _, address := range addresses {
		if !allowedIP(address.IP) {
			return nil, errors.New("upstream resolves to a prohibited address")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}

func newHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy: nil, DialContext: guardedDial, ForceAttemptHTTP2: true,
		MaxIdleConns: 128, MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
