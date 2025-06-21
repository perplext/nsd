//go:build !windows

package main

import "os"

// checkPrivileges checks if the program has necessary privileges
func checkPrivileges() bool {
	return os.Geteuid() == 0
}