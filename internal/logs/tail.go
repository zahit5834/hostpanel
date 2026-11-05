package logs

import (
	"bytes"
	"io"
	"os"
)

const tailChunk = 32 * 1024

// MaxLineBytes truncates absurdly long lines so one bad line cannot blow the RAM budget.
const MaxLineBytes = 8 * 1024

// TailLines returns up to n last lines of the file at path, oldest first.
// It reads backwards in fixed-size chunks, so memory use is bounded by the
// returned lines (each capped at MaxLineBytes) regardless of file size.
func TailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return tailReader(f, n)
}

func tailReader(f io.ReadSeeker, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	var (
		lines   [][]byte // collected newest-first
		partial []byte   // bytes of the line currently being assembled (may be truncated)
		buf     = make([]byte, tailChunk)
		pos     = size
		first   = true
	)
	for pos > 0 && len(lines) < n {
		readSize := int64(tailChunk)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		if _, err := f.Seek(pos, io.SeekStart); err != nil {
			return nil, err
		}
		chunk := buf[:readSize]
		if _, err := io.ReadFull(f, chunk); err != nil {
			return nil, err
		}
		// Drop the file's trailing newline so it does not produce an empty last line.
		if first {
			chunk = bytes.TrimSuffix(chunk, []byte("\n"))
			first = false
		}
		for len(chunk) > 0 && len(lines) < n {
			i := bytes.LastIndexByte(chunk, '\n')
			seg := chunk[i+1:]
			partial = prependCapped(seg, partial)
			if i < 0 {
				break // line continues in the previous chunk
			}
			lines = append(lines, partial)
			partial = nil
			chunk = chunk[:i]
		}
	}
	if pos == 0 && len(lines) < n && partial != nil {
		lines = append(lines, partial)
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[len(lines)-1-i] = string(l)
	}
	return out, nil
}

// prependCapped returns seg+tail, keeping only the first MaxLineBytes bytes of the line.
// Because we read backwards, the kept part is the line's tail end; that is fine
// for logs (the message end usually has the error) and keeps memory bounded.
func prependCapped(seg, tail []byte) []byte {
	if len(tail) >= MaxLineBytes {
		return tail
	}
	room := MaxLineBytes - len(tail)
	if len(seg) > room {
		seg = seg[len(seg)-room:]
	}
	out := make([]byte, 0, len(seg)+len(tail))
	out = append(out, seg...)
	return append(out, tail...)
}
