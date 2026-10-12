package zeek

import (
	"errors"
	"io/fs"
	"log/slog"
)

// Zeek creates each log file when it writes the file's first line, so a log can be
// missing for a while: until the first TLS connection for ssl.log, until the first
// alert for notice.log, and briefly after each rotation. The pollers check every few
// seconds; these helpers make each change of state show up in the logs once.

// fileState is what a poller last found at its log's path.
type fileState int

const (
	fileUnchecked  fileState = iota
	fileMissing              // not created yet, or between rotations: normal
	fileUnreadable           // exists but can't be opened, e.g. permissions
	fileOpen
)

// zeekLog names a log for the state messages.
type zeekLog struct {
	name      string // "ssl.log"
	createdBy string // why it may not exist yet
	gives     string // what hexwall reads from it
}

var (
	sslLog    = zeekLog{name: "ssl.log", createdBy: "Zeek creates it at the first TLS connection it sees", gives: "TLS server names"}
	noticeLog = zeekLog{name: "notice log", createdBy: "Zeek creates it at its first alert", gives: "DNS-bypass alerts"}
)

// reportOpened logs that the file can be read, if that's news.
func (l zeekLog) reportOpened(state *fileState, path string) {
	if *state != fileOpen {
		slog.Info("zeek: "+l.name+" found, watching for "+l.gives, "path", path)

		*state = fileOpen
	}
}

// reportOpenError logs why the file can't be opened, if that's news, and reports
// whether it is missing. When it is, whatever appears at the path next is a new file,
// which the caller must read from the start.
func (l zeekLog) reportOpenError(state *fileState, path string, err error) (missing bool) {
	if errors.Is(err, fs.ErrNotExist) {
		if *state != fileMissing {
			slog.Info("zeek: waiting for "+l.name+"; "+l.createdBy, "path", path)

			*state = fileMissing
		}

		return true
	}

	if *state != fileUnreadable {
		slog.Warn("zeek: cannot open "+l.name+"; "+l.gives+" are not being read", "path", path, "err", err)

		*state = fileUnreadable
	}

	return false
}
