package utils

import (
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1 << 20, "1.00 MB"},
		{3*(1<<20) + 512*(1<<10), "3.50 MB"},
		{1<<30 + 1, "1.00 GB"},
		{1<<40 + 1, "1.00 TB"},
	}
	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q; want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	now := time.Now()
	cases := []struct {
		desc       string
		t          time.Time
		wantExact string
	}{
		{"recent", now.Add(-30 * time.Second), "just now"},
		{"minutes", now.Add(-30 * time.Minute), "30 min ago"},
		{"hours", now.Add(-2 * time.Hour), "2 hours ago"},
	}
	for _, c := range cases {
		got := FormatTime(c.t)
		if got != c.wantExact {
			t.Errorf("%s: FormatTime(%v) = %q; want %q", c.desc, c.t, got, c.wantExact)
		}
	}
	// Test default (>= 24h)
	long := now.Add(-48 * time.Hour)
	want := long.Format("Jan 02 15:04")
	if got := FormatTime(long); got != want {
		t.Errorf("FormatTime(long) = %q; want %q", got, want)
	}
}
