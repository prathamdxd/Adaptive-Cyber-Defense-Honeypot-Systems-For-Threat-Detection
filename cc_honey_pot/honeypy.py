import argparse
from ssh_honeypot import honeypot  
from web_honeypot import run_web_honeypot  

def main():
    parser = argparse.ArgumentParser(description="Run a honeypot server for SSH or HTTP.")
    
    parser.add_argument('-a', '--address', type=str, required=True, help="The IP address to bind the honeypot to.")
    parser.add_argument('-p', '--port', type=int, required=True, help="The port to bind the honeypot to.")
    parser.add_argument('-u', '--username', type=str, help="Username for authentication (optional).")
    parser.add_argument('-pw', '--password', type=str, help="Password for authentication (optional).")
    parser.add_argument('-s', '--ssh', action="store_true", help="Run an SSH honeypot.")
    parser.add_argument('-w', '--http', action="store_true", help="Run an HTTP honeypot.")

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(
                address=args.address,
                port=args.port,
                username=args.username or "default_user",
                password=args.password or "default_password"
            )

        elif args.http:
            print("[-] Running HTTP Honeypot...")
            username = args.username or "admin" 
            password = args.password or "password"  
            print(f"Port: {args.port}, Username: {username}, Password: {password}")
            run_web_honeypot(
                port=args.port,
                username=username,
                password=password
            )
        else:
            print("[-] Please choose a honeypot type (SSH --ssh) or (HTTP --http).")

    except Exception as e:
        print(f"\n[!] Error occurred: {e}\nExiting HONEYPOT...\n")

if __name__ == "__main__":
    main()
