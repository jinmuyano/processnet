package cni0

import (
	"fmt"
	"testing"
)

func TestGetProcesses(t *testing.T) {
	data, err := GetProcesses([]string{"java"})
	if err != nil {
		fmt.Println("错误喽", err)
	}
	fmt.Println(data)
}
