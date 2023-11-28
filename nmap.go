package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	targetFlag string
	portFlag   int
	outputFlag string

	liveIPsMu sync.Mutex
	liveIPs   []string
)

func init() {
    printBanner()
	flag.StringVar(&targetFlag, "target", "", "Specify target IP range (e.g., 192.168.1.1-20)")
	flag.IntVar(&portFlag, "port", 80, "Specify target port for scanning")
	flag.StringVar(&outputFlag, "output", "live_ips.txt", "Specify the output file for live IPs")
}
func printBanner() {
	fmt.Println("\033[01;34m╔══════════════════════════════════════════════════╗")
	fmt.Println("\033[01;34m║\033[01;31m                  C O D E B A N                   \033[01;34m║")
	fmt.Println("\033[01;34m╚══════════════════════════════════════════════════╝")
}

func main() {
	flag.Parse()

	if targetFlag == "" {
		fmt.Println("Please specify a target IP range using the -target flag.")
		os.Exit(1)
	}
           printBanner()
	fmt.Println("Scanning in progress: [=>                  ] 0% Complete (Approx. calculating)  Live IPs: 0")

	targetIPs, err := expandIPRange(targetFlag)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	progressBar := NewProgressBar(len(targetIPs))

	for _, ip := range targetIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if scanPort(ip, portFlag) {
				liveIPsMu.Lock()
				liveIPs = append(liveIPs, ip)
				liveIPsMu.Unlock()
			}

			progressBar.Increment()
		}(ip)
	}

	wg.Wait()

	saveLiveIPs(outputFlag)

	fmt.Println("\n[INFO] Live IPs saved to", outputFlag)
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
