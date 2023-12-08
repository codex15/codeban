package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

var (
	targetFlag string
	portFlag   int
	outputFlag string

	liveIPsMu sync.Mutex
	liveIPs   []string

	numThreads = 10 // Default number of threads
)

func main() {
	if len(os.Args) < 5 {
		printUsage()
		os.Exit(1)
	}

	targetFlag = os.Args[1]
	portFlag = parseInt(os.Args[2])
	outputFlag = os.Args[3]
	numThreads = parseInt(os.Args[4])

	if targetFlag == "" {
		fmt.Println("Please specify a target IP range.")
		os.Exit(1)
	}

	printBanner()
	fmt.Printf("Scanning in progress for target %s on port %d with %d threads...\n", targetFlag, portFlag, numThreads)

	targetIPs, err := expandIPRange(targetFlag)
	if err != nil {
		log.Fatal(err)
	}

	var g errgroup.Group

	ipChan := make(chan string, numThreads)

	// Create a ProgressBar
	progressBar := NewProgressBar(len(targetIPs))

	for i := 0; i < numThreads; i++ {
		g.Go(func() error {
			return scanWorker(ipChan, portFlag, progressBar)
		})
	}

	go func() {
		for _, ip := range targetIPs {
			ipChan <- ip
		}
		close(ipChan)
	}()

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}

	saveLiveIPs(outputFlag)

	fmt.Printf("\n[INFO] Live IPs saved to %s\n", outputFlag)
}

func printUsage() {
	fmt.Println("Usage: ./scan <target> <port> <output> <threads>")
}

func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║                  C O D E B A N                   ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
}

func expandIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format")
	}

	start := net.ParseIP(parts[0])
	if start == nil {
		return nil, fmt.Errorf("invalid start IP address")
	}

	end := net.ParseIP(parts[1])
	if end == nil {
		return nil, fmt.Errorf("invalid end IP address")
	}

	var ips []string

	for ip := start; !ip.Equal(end); {
		ips = append(ips, ip.String())
		ip = nextIP(ip)
	}

	// Include the end IP in the list
	ips = append(ips, end.String())

	return ips, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

func scanPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func saveLiveIPs(outputFile string) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for _, ip := range liveIPs {
		file.WriteString(ip + "\n")
	}
}

type ProgressBar struct {
	Total    int
	Progress int
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		Total:    total,
		Progress: 0,
	}
}

func (p *ProgressBar) Increment() {
	p.Progress++
	p.Print()
}

func (p *ProgressBar) Print() {
	progressPercentage := int(float64(p.Progress) / float64(p.Total) * 100)
	fmt.Printf("\rScanning in progress: [%s] %d%% Complete  Live IPs: %d", strings.Repeat("=>", progressPercentage/2), progressPercentage, len(liveIPs))
}

func scanWorker(ipChan <-chan string, port int, progressBar *ProgressBar) error {
	for ip := range ipChan {
		if scanPort(ip, port) {
			liveIPsMu.Lock()
			liveIPs = append(liveIPs, ip)
			liveIPsMu.Unlock()
		}
		progressBar.Increment()
	}
	return nil
}

func parseInt(s string) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("Error converting %s to int: %v", s, err)
	}
	return val
}
