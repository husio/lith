package email

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// NewFilesystemServer returns a mail Server implementation that is using the
// local filesystem to store sent messages. This implementation should be used
// for tests only.
func NewFilesystemServer(dir string) Server {
	_ = os.MkdirAll(dir, 0770)
	return fs{dir: dir}
}

type fs struct {
	dir string
}

func (f fs) Send(from, to, subject string, body []byte) error {
	name := mailFilename(subject)
	fs, err := os.Create(filepath.Join(f.dir, name))
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	_, _ = fmt.Fprintf(fs, "From\t%s\n", from)
	_, _ = fmt.Fprintf(fs, "To\t%s\n", to)
	_, _ = fmt.Fprintf(fs, "Subject\t%s\n", subject)
	_, _ = fmt.Fprintf(fs, "\n%s\n\n", strings.Repeat("@", 78))
	_, _ = fmt.Fprintln(fs, string(body))
	if err := fs.Close(); err != nil {
		return fmt.Errorf("sync email file: %w", err)
	}
	return nil
}

func mailFilename(sub string) string {
	name := regexp.MustCompile(`[^a-zA-Z0-9_]+`).ReplaceAllString(sub, "_")
	name = regexp.MustCompile(`_+`).ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	name = fmt.Sprintf("%d_%s.email", time.Now().UnixNano(), name)
	return name
}
