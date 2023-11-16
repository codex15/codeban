# Brute

Brute is a powerful yet lightweight SSH brute-force tool written in Go. It is designed to provide a flexible and efficient way to perform brute-force attacks on SSH servers.

## Features

- **Concurrency**: Execute multiple login attempts concurrently, making the brute-force process faster.
- **Customizable Commands**: Define custom commands to execute upon successful login, tailoring the tool to your specific needs.
- **Colorful Output**: Color-coded console output for improved readability, providing a clear distinction between successful and unsuccessful attempts.

## Usage

To run Brute, use the following command:

```bash
go run test2.go <userpass file> <custom command> <ip list file> <port> <threads>
<userpass file>: Path to a file containing username:password pairs.
<custom command>: Custom command to execute upon successful login.
<ip list file>: Path to a file containing a list of target IPs.
<port>: Target SSH port for connection.
<threads>: Number of concurrent threads to use.
Installation
Clone the repository:
git clone https://github.com/codex15/codeban.git
cd codeban
Run the program:
go run brute.go <userpass file> <custom command> <ip list file> <port> <threads>
Contributing
We welcome contributions! Feel free to open issues for bug reports or new features. Pull requests are also highly appreciated.

