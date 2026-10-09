//go:build !linux

package main

// Process command-line rewriting is currently supported only on Linux.
func privateProcessArgs(args []string) []string { return args }
