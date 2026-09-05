package config

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// newCommentStripper returns a reader over src with whole-line "//" comments
// removed, so config files may be annotated. Inline // is left untouched to
// avoid corrupting values such as URLs.
func newCommentStripper(src []byte) io.Reader {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return &out
}
