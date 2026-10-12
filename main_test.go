package main

import (
	"testing"

	"github.com/hexbytedev/hexwall/internal/monitor"
)

func TestPrivilegeCheck(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		euid      int
		wantFatal bool
		wantMsg   bool
	}{
		{"root enforce", monitor.ModeEnforce, 0, false, false},
		{"root watch", monitor.ModeWatch, 0, false, false},
		{"user enforce refuses", monitor.ModeEnforce, 1000, true, true},
		{"user watch warns", monitor.ModeWatch, 1000, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fatal, msg := privilegeCheck(tt.mode, tt.euid)
			if fatal != tt.wantFatal || (msg != "") != tt.wantMsg {
				t.Fatalf("privilegeCheck(%q, %d) = %v, %q; want fatal %v, message %v", tt.mode, tt.euid, fatal, msg, tt.wantFatal, tt.wantMsg)
			}
		})
	}
}
