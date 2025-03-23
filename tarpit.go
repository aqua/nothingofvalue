package nothingofvalue

import (
	"cmp"
	"io"
	rand "math/rand/v2"
	"net/http"
	"time"
)

type TarpitWriter struct {
	w           io.Writer
	chunk       int
	chunkJitter int
	delay       time.Duration
	jitter      time.Duration
	httpRC      *http.ResponseController
}

func min[T cmp.Ordered](a T, b T) T {
	if cmp.Less(a, b) {
		return a
	}
	return b
}

func max[T cmp.Ordered](a T, b T) T {
	if cmp.Less(a, b) {
		return b
	}
	return a
}

func (tw *TarpitWriter) Write(p []byte) (n int, err error) {
	written := 0
	for pos := 0; pos < len(p); {
		jl := 0
		if tw.chunkJitter > 0 {
			jl = rand.IntN(tw.chunkJitter)
		}
		cs := max(1, tw.chunk+jl)
		end := min(pos+cs, len(p))
		chunk := p[pos:end]
		pos = end
		if n, err := tw.w.Write(chunk); err == nil {
			written += n
			dl := 0
			if tw.jitter > 0 {
				dl = rand.IntN(int(tw.jitter))
			}
			if tw.httpRC != nil {
				tw.httpRC.Flush()
			}
			time.Sleep(tw.delay + time.Duration(dl))
		} else {
			return written + n, err
		}
	}
	return written, nil
}
