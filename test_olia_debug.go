//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

func main() {
	fmt.Println("Testing OLIA SmoothedBytesBetweenLosses...")

	sharedState := quic.NewOLIASharedState()
	olia := quic.NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	fmt.Println("Initial smoothed:", olia.SmoothedBytesBetweenLosses())

	fmt.Println("ACK packet 1...")
	olia.OnPacketAcked(1, 1000, 0, time.Now())

	fmt.Println("ACK packet 2...")
	olia.OnPacketAcked(2, 1000, 0, time.Now())

	fmt.Println("Loss event...")
	olia.OnCongestionEvent(3, 1200, 5000)

	fmt.Println("ACK packet 4...")
	olia.OnPacketAcked(4, 2000, 0, time.Now())

	fmt.Println("Done")
}
