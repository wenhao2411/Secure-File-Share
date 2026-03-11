from client_class import Client
import sys


if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 6767

    # Parse CLI arguments
    if len(sys.argv) >= 2:
        HOST = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            PORT = int(sys.argv[2])
        except ValueError:
            print("[!] Port must be an integer")
            sys.exit(1)

    Client(HOST, PORT).connect()