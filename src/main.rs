use std::env;
use std::io::Read;
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let test_mode = args.iter().any(|arg| arg == "--test");
    let debug_mode = args.iter().any(|arg| arg == "--debug");

    println!("Simple P2P Messenger");

    // Ввод параметров
    print!("Enter your username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    print!("Enter password: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim().to_string();

    // Канал для передачи адреса сервера
    let (tx, rx) = mpsc::channel();

    // Запуск сервера в отдельном потоке
    let server_password = password.clone();
    let server_thread = thread::spawn(move || {
        if let Err(e) = run_server(server_password, tx, debug_mode) {
            eprintln!("Server error: {}", e);
        }
    });

    // Получение адреса сервера
    let server_addr = rx.recv().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to receive server address: {}", e),
        )
    })?;

    println!("Your server is listening on: {}", server_addr);

    // В обычном режиме запрашиваем адрес собеседника
    let contact_addr = if test_mode {
        server_addr // В тестовом режиме подключаемся к самим себе
    } else {
        println!("Please enter contact IP:PORT (e.g., 127.0.0.1:8080)");
        print!("Contact address: ");
        io::stdout().flush()?;
        let mut contact = String::new();
        io::stdin().read_line(&mut contact)?;
        let contact = contact.trim().to_string();

        let parts: Vec<&str> = contact.split(':').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid contact format. Use IP:PORT",
            ));
        }
        let contact_ip = parts[0];
        let contact_port: u16 = parts[1]
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port number"))?;

        SocketAddr::new(
            contact_ip
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IP address"))?,
            contact_port,
        )
    };

    // Клиентский цикл
    run_client(
        &username,
        contact_addr.ip().to_string().as_str(),
        contact_addr.port(),
        &password,
        debug_mode,
    )?;

    // Ожидаем завершение серверного потока
    let _ = server_thread.join();
    Ok(())
}

fn run_server(
    password: String,
    addr_sender: mpsc::Sender<SocketAddr>,
    debug_mode: bool,
) -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let local_addr = listener.local_addr()?;

    // Отправляем адрес сервера
    addr_sender.send(local_addr).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to send server address: {}", e),
        )
    })?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut data = Vec::new();
                let mut buffer = [0; 1024];

                loop {
                    let n = stream.read(&mut buffer)?;
                    data.extend_from_slice(&buffer[..n]);
                    if n < buffer.len() {
                        break;
                    }
                }

                let ciphertext = String::from_utf8_lossy(&data);
                if debug_mode {
                    println!("[DEBUG] Received encrypted message:\n{}", ciphertext);
                }

                match decrypt(&ciphertext, &password, debug_mode) {
                    Ok(plaintext) => {
                        if debug_mode {
                            println!("[DEBUG] Decrypted message: {}", plaintext);
                        }
                        println!("\n{}", plaintext);
                        print!("> ");
                        io::stdout().flush()?;
                    }
                    Err(e) => eprintln!("\nDecryption failed: {}", e),
                }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    Ok(())
}

fn run_client(
    username: &str,
    ip: &str,
    port: u16,
    password: &str,
    debug_mode: bool,
) -> io::Result<()> {
    println!("Connecting to {}:{}", ip, port);
    println!("Type messages (Ctrl+C to exit):");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let message = line?;
        if message.is_empty() {
            continue;
        }

        print!("> ");
        io::stdout().flush()?;

        // Форматируем сообщение: USERNAME: MESSAGE
        let full_message = format!("{}: {}", username, message);
        if debug_mode {
            println!("[DEBUG] Plaintext message: {}", full_message);
        }

        match encrypt(&full_message, password, debug_mode) {
            Ok(ciphertext) => {
                if debug_mode {
                    println!("[DEBUG] Encrypted message:\n{}", ciphertext);
                }
                match TcpStream::connect((ip, port)) {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(ciphertext.as_bytes()) {
                            eprintln!("Send failed: {}", e);
                        } else if debug_mode {
                            println!("[DEBUG] Message sent successfully");
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection to {}:{} failed: {}", ip, port, e);
                    }
                }
            }
            Err(e) => eprintln!("Encryption failed: {}", e),
        }
    }
    Ok(())
}

fn encrypt(data: &str, password: &str, debug_mode: bool) -> io::Result<String> {
    // В debug_mode выводим полную информацию о GPG
    let stderr = if debug_mode {
        Stdio::inherit()
    } else {
        Stdio::null()
    };

    let mut child = Command::new("gpg")
        .args([
            "--symmetric",
            "--batch",
            "--armor",
            "--passphrase",
            password,
            "--compress-algo",
            "none",
            "--no-symkey-cache",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        if debug_mode {
            eprintln!(
                "[DEBUG] GPG encryption failed with status: {}",
                output.status
            );
            eprintln!(
                "[DEBUG] GPG stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "GPG encryption failed",
        ))
    }
}

fn decrypt(data: &str, password: &str, debug_mode: bool) -> io::Result<String> {
    // В debug_mode выводим полную информацию о GPG
    let stderr = if debug_mode {
        Stdio::inherit()
    } else {
        Stdio::null()
    };

    let mut child = Command::new("gpg")
        .args([
            "--decrypt",
            "--batch",
            "--passphrase",
            password,
            "--no-symkey-cache",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        if debug_mode {
            eprintln!(
                "[DEBUG] GPG decryption failed with status: {}",
                output.status
            );
            eprintln!(
                "[DEBUG] GPG stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "GPG decryption failed",
        ))
    }
}
