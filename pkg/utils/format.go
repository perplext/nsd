package utils

import (
	"fmt"
	"time"
)

// FormatBytes formats bytes into a human-readable string
func FormatBytes(bytes uint64) string {
	const (
		_          = iota
		KB float64 = 1 << (10 * iota)
		MB
		GB
		TB
	)

	switch {
	case bytes >= uint64(TB):
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= uint64(GB):
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= uint64(MB):
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= uint64(KB):
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatTime formats a time.Time into a readable string
func FormatTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		minutes := int(diff.Minutes())
		return fmt.Sprintf("%d min ago", minutes)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		return fmt.Sprintf("%d hours ago", hours)
	default:
		return t.Format("Jan 02 15:04")
	}
}
