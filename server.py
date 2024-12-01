import socket
import json
import base64
import os
import hmac
import hashlib
import logging
from diffieHellman import DiffieHellman
from cryp_util import CryptoUtils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DH_Server')

class SecureServer:
    def __init__(self, host='0.0.0.0', port=4000):
        self.host = host
        self.port = port
        self.dh = DiffieHellman()
        self.server_socket = None
        self.encryption_key = None
        # Pre-shared authentication key (in production, use proper key management)
        self.auth_key = b"server_secret_key"

    def authenticate_client(self, client_socket):
        """Implement challenge-response authentication."""
        # Generate random challenge
        challenge = base64.b64encode(os.urandom(32)).decode()
        client_socket.send(challenge.encode())
        
        # Receive client response
        response = client_socket.recv(1024)
        expected_response = hmac.new(self.auth_key, challenge.encode(), 
                                   hashlib.sha256).digest()
        
        return hmac.compare_digest(response, expected_response)

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)

            # Get the actual IP address of the server to display
            hostname = socket.gethostname()
            server_ip = socket.gethostbyname(hostname)
            print(f"\n=== Secure Chat Server ===")
            print(f"Server IP address: {server_ip}")
            print(f"Listening for connections on port {self.port}...")


            while True:
                client_socket, address = self.server_socket.accept()
                logger.info(f"Connection from {address}")

                try:
                    # Authenticate client
                    if not self.authenticate_client(client_socket):
                        logger.warning("Client authentication failed")
                        client_socket.close()
                        continue

                    # Exchange public keys
                    client_socket.send(str(self.dh.public_key).encode())
                    client_public_key = int(client_socket.recv(1024).decode())

                    # Generate shared secret and derive encryption key
                    shared_secret = self.dh.generate_shared_secret(client_public_key)
                    salt = os.urandom(16)
                    client_socket.send(salt)
                    self.encryption_key = CryptoUtils.derive_key(shared_secret, salt)

                    # Handle encrypted communication
                    self.handle_client(client_socket)

                except Exception as e:
                    logger.error(f"Error handling client: {e}")
                finally:
                    client_socket.close()

        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_client(self, client_socket):
        print("\nClient connected. Waiting for messages...")
        while True:
            try:
                # Receive encrypted message and MAC
                data = client_socket.recv(4096)
                if not data:
                    break
                
                message_data = json.loads(data.decode())
                encrypted_message = base64.b64decode(message_data['message'])
                mac = base64.b64decode(message_data['mac'])

                # Decrypt and verify message
                decrypted_message = CryptoUtils.decrypt_message(
                    self.encryption_key, encrypted_message, mac
                )
                logger.info(f"Received: {decrypted_message}")

                # Send encrypted response
                response = f"Server received: {decrypted_message}"
                enc_response, mac = CryptoUtils.encrypt_message(
                    self.encryption_key, response
                )
                
                response_data = {
                    'message': base64.b64encode(enc_response).decode(),
                    'mac': base64.b64encode(mac).decode()
                }
                client_socket.send(json.dumps(response_data).encode())

            except Exception as e:
                logger.error(f"Error in client communication: {e}")
                break

        print("\nClient disconnected")

if __name__ == "__main__":
    server = SecureServer()
    server.start()
    print("Server Started.")