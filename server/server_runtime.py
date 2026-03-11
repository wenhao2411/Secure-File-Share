from server_class import Server
import sys


if __name__ == "__main__":

    host = "127.0.0.1"
    port = 6767

    # Parse CLI arguments
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("[!] Port must be an integer")
            sys.exit(1)

    print("=" * 50)
    print(" SecureShare Server")
    print("=" * 50)
    print(f"Host: {host}")
    print(f"Port: {port}")
    print("=" * 50)

    # Start server
    server = Server(host=host, port=port)
    server.start()