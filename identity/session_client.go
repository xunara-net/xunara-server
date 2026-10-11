package identity

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"
)

const MaxSessionUserAgentBytes = 512

// SessionClientInfo 仅用于安全记录；IP 与客户端自报 UA 均不能授予身份或权限。
type SessionClientInfo struct {
	IP        string
	UserAgent string
}

func (info SessionClientInfo) Normalize() SessionClientInfo {
	address, err := netip.ParseAddr(strings.TrimSpace(info.IP))
	if err == nil && address.Zone() == "" {
		info.IP = address.Unmap().String()
	} else {
		info.IP = ""
	}
	var agent strings.Builder
	for _, character := range info.UserAgent {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || character == unicode.ReplacementChar {
			continue
		}
		encoded := string(character)
		if agent.Len()+len(encoded) > MaxSessionUserAgentBytes {
			break
		}
		agent.WriteString(encoded)
	}
	info.UserAgent = strings.TrimSpace(agent.String())
	return info
}

func singleSessionClientInfo(infos []SessionClientInfo) (SessionClientInfo, error) {
	if len(infos) > 1 {
		return SessionClientInfo{}, errors.New("identity: multiple session client sources")
	}
	if len(infos) == 1 {
		return infos[0].Normalize(), nil
	}
	return SessionClientInfo{}, nil
}
