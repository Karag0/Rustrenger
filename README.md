# Rustrenger
P2p messenger on Rust with GPG encryption
A minimal peer-to-peer messaging application written in Rust that uses GPG for symmetric encryption. Allows secure communication between two peers over TCP.
Features

    Symmetric encryption using GPG
    Peer-to-peer TCP communication
    Self-contained server/client architecture
    Test mode for local testing
    Debug mode for detailed logging


Requirements

    Rust toolchain
    GNU Privacy Guard (GPG) installed
    TCP connectivity between peers

**Installation:**
# Clone repository
git clone https://github.com/Karag0/Rustrenger.git

cd p2p-messenger

# Build
cargo build
cd target/debug

# Run
./rustrenger
# Extra options:
--test for self connection
--debug for debug information from GPG
