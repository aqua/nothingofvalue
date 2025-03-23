package nothingofvalue

import (
	"bytes"
	"io"
	"testing"
)

func TestMax(t *testing.T) {
	if v := max(54, 52); v != 54 {
		t.Errorf("max(54,52)=%d, want 54", v)
	}
}

func TestMin(t *testing.T) {
	if v := min(54, 52); v != 52 {
		t.Errorf("min(54,52)=%d, want 52", v)
	}
}

func TestTarpitWrite(t *testing.T) {
	src := []byte("abcdefghijklmnopqrstuvqxyzABCDEFGHIJKLMNOPQRSTUVQXYZ")
	dst := &bytes.Buffer{}
	tw := &TarpitWriter{w: dst}
	n, err := io.Copy(tw, bytes.NewBuffer(src))
	if err != nil {
		t.Errorf("error tarpit-copying: %v", err)
	} else if n != int64(len(src)) {
		t.Errorf("copy returned wrong byte count: want %d, got %d", len(src), n)
	}
	if !bytes.Equal(src, dst.Bytes()) {
		t.Errorf("bad copy: want %q, got %q", src, dst)
	}
}

func TestTarpitWriteChunk(t *testing.T) {
	src := []byte("abcdefghijklmnopqrstuvqxyzABCDEFGHIJKLMNOPQRSTUVQXYZ")
	dst := &bytes.Buffer{}
	tw := &TarpitWriter{w: dst, chunk: 9}
	n, err := io.Copy(tw, bytes.NewBuffer(src))
	if err != nil {
		t.Errorf("error tarpit-copying: %v", err)
	} else if n != int64(len(src)) {
		t.Errorf("copy returned wrong byte count: want %d, got %d", len(src), n)
	}
	if !bytes.Equal(src, dst.Bytes()) {
		t.Errorf("bad copy: want %q, got %q", src, dst)
	}
}

func TestTarpitWriteChunkJitter(t *testing.T) {
	src := []byte("abcdefghijklmnopqrstuvqxyzABCDEFGHIJKLMNOPQRSTUVQXYZ")
	dst := &bytes.Buffer{}
	tw := &TarpitWriter{w: dst, chunk: 9, chunkJitter: 5}
	n, err := io.Copy(tw, bytes.NewBuffer(src))
	if err != nil {
		t.Errorf("error tarpit-copying: %v", err)
	} else if n != int64(len(src)) {
		t.Errorf("copy returned wrong byte count: want %d, got %d", len(src), n)
	}
	if !bytes.Equal(src, dst.Bytes()) {
		t.Errorf("bad copy: want %q, got %q", src, dst)
	}
}
