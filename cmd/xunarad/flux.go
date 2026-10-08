package main

import (
	"errors"
	"time"

	"github.com/xunara-net/xunara-server/control"
)

// fluxConfigFor builds the Xunara Flux configuration for one deployment.
//
// The feature stays off (nil) unless enabled explicitly: a control-plane
// file-storage subsystem must not appear on upgrade by itself (the same
// fail-closed default as Reach). Settings without the enable switch are a
// configuration error rather than being silently ignored. Range checks
// (size/TTL/quotas) happen in control.New, whose error names the deployment.
func fluxConfigFor(enabled bool, dir string, maxSize int64, ttl time.Duration) (*control.FluxConfig, error) {
	if !enabled {
		if dir != "" || maxSize != 0 || ttl != 0 {
			return nil, errors.New("flux settings require enabling Flux")
		}
		return nil, nil
	}
	return &control.FluxConfig{Dir: dir, MaxSize: maxSize, TTL: ttl}, nil
}
