# Brute 🔐

Welcome to Brute, your trusty sidekick in the world of SSH exploration. This robust and stealthy tool empowers you to navigate the digital realm with finesse.

## ⚙️ Features

- **Blazing Speed**: Execute lightning-fast login attempts concurrently, leaving sluggish servers in the dust.
- **Custom Commands**: Craft your personalized commands to unleash havoc upon successful infiltrations.
- **Chromatic Symphony**: Revel in the colorful console output, where victories and defeats are vividly painted.

## 🚀 Usage

- Fire up Brute with the command:
- ```bash
go run brute.go <userpass file> <custom command> <ip list file> <port> <threads> [-S <IP segment>] [-P <ports file>]
<userpass file>: The treasure trove of username:password pairs.
<custom command>: Your secret weapon, a custom command to deploy upon victorious conquest.
<ip list file>: A map of target IPs to conquer.
<port>: The gate to infiltrate, the SSH port.
<threads>: The legion of threads to lead into battle.
[-S <IP segment>]: Optional. Specify an IP segment in CIDR notation to filter target IPs.

🛠️ Installation

- Clone the Lair:
git clone https://github.com/codex15/codeban.git
cd codeban

- Summon the Spirits:
go run brute.go <userpass file> <custom command> <ip list file> <port> <threads> [-S <IP segment>] [-P <ports file>]

🎭 Contributing

Join our clandestine society! Open issues for bug bounties or propose enhancements. Contribute your craft through pull requests.

📜 License

Brute is licensed under the MIT License. Hack responsibly.
#
