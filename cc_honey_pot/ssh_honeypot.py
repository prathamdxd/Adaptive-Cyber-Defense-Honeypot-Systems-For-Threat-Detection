import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
from pathlib import Path

SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
logging_format = logging.Formatter('%(asctime)s - %(message)s')

base_dir = Path(__file__).resolve().parent
static_dir = base_dir / 'static'
server_key_path = static_dir / 'server.key'

desc_file_path = base_dir / "desc.txt"
desc_file_password = "show"  


if not server_key_path.exists():
    print(f"Server key not found at {server_key_path}, generating a new one...")
    static_dir.mkdir(parents=True, exist_ok=True)
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(str(server_key_path))
    print(f"New server key generated at {server_key_path}")
else:
    host_key = paramiko.RSAKey(filename=str(server_key_path))


if not desc_file_path.exists():
    desc_file_path.write_text(
        "Description of SSH Honeypot:"
        "This honeypot is designed to simulate a vulnerable SSH server."
        "Logs all commands executed by attackers."
        "Simulates a basic file system and supports common Linux commands."
        "Access to this file requires a password via the `cat` command."
    )


funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

FAKE_FILE_SYSTEM = {
    '/': ['home', 'etc', 'var', 'file1.txt', 'desc.txt'],
    '/home': ['user1', 'user2'],
    '/home/user1': ['secrets.txt', 'notes.txt'],
    '/etc': ['config.cfg', 'network.cfg'],
    '/var': []
}

def emulated_shell(channel, client_ip):
    current_path = ['/']
    channel.send(b'Adaptive Cyber Defence: HONEYPOT System For Threat Detection$ ')
    command = b""
    while True:
        char = channel.recv(1)
        if not char:
            channel.close()
            break

        channel.send(char)
        command += char

        if char == b'\r':
            command = command.strip()
            command_decoded = command.decode()

            if command_decoded == "exit":
                channel.send(b'\n Goodbye!\n')
                channel.close()
                break
            elif command_decoded == "pwd":
                path = "/".join(current_path)
                response = f'\n{path}\n'.encode()
            elif command_decoded.startswith("ls"):
                path = "/".join(current_path)
                files = FAKE_FILE_SYSTEM.get(path, [])
                response = b'\n' + b'\n'.join([file.encode() for file in files]) + b'\n'
            elif command_decoded.startswith("cd"):
                parts = command_decoded.split(' ', 1)
                if len(parts) < 2:
                    response = b'\nUsage: cd <directory>\n'
                else:
                    new_dir = parts[1].strip()
                    if new_dir == "..":
                        if len(current_path) > 1:
                            current_path.pop()
                        response = b'\nMoved to parent directory\n'
                    elif new_dir.startswith("/"):
                        if new_dir in FAKE_FILE_SYSTEM:
                            current_path = new_dir.split("/")
                            response = f'\nChanged directory to {new_dir}\n'.encode()
                        else:
                            response = b'\nNo such directory\n'
                    else:
                        new_path = "/".join(current_path + [new_dir])
                        if new_path in FAKE_FILE_SYSTEM:
                            current_path.append(new_dir)
                            response = f'\nChanged directory to {new_path}\n'.encode()
                        else:
                            response = b'\nNo such directory\n'
            elif command_decoded.startswith("cat"):
                parts = command_decoded.split(' ')
                if len(parts) < 2:
                    response = b'\nUsage: cat <filename>\n'
                else:
                    file_name = parts[1]
                    if file_name == "desc.txt":
                        channel.send(b'\nEnter password to view desc.txt: ')
                        password = b""
                        while True:
                            char = channel.recv(1)
                            if char == b'\r':
                                break
                            channel.send(char)
                            password += char
                        if password.decode().strip() == desc_file_password:
                            creds_logger.info(f'{client_ip} successfully accessed desc.txt.')
                            response = f'\n{desc_file_path.read_text()}\n'.encode()
                        else:
                            creds_logger.warning(f'{client_ip} failed to access desc.txt.')
                            response = b'\nInvalid password! Access denied.\n'
                    else:
                        path = "/".join(current_path)
                        if file_name in FAKE_FILE_SYSTEM.get(path, []):
                            response = f'\nContent of {file_name}:\n[This is sensitive data]\n'.encode()
                        else:
                            response = b'\nFile not found\n'
            else:
                response = b'\nUnknown command: ' + command + b'\n'

            creds_logger.info(f'{client_ip} - Command Executed: {command_decoded}')
            channel.send(response)
            channel.send(b'Adaptive Cyber Defence: HONEYPOT System For Threat Detection$ ')
            command = b""

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auth(self, username: str = None) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip},{username},{password}')
        if self.input_username and self.input_password:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(10)
        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "Welcome to Ubuntu 22.04 LTS\n(Team 10 :\t Prathamesh V\t Niteesh Raj\t P Kiran \t N M Manikanta)\n\t\t\t"
        channel.send(standard_banner.encode())
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(f"Error: {error}")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(f"Transport Close Error: {error}")
        client.close()

def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(1000)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(f"Error in honeypot: {error}")

honeypot('0.0.0.0', 2223, 'username', 'password')
 