import socket
import json
import base64
import hmac
import hashlib
import logging
from diffieHellman import DiffieHellman
from cryp_util import CryptoUtils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DH_Client')

class SecureClient:
    def __init__(self):
        self.host = None
        self.port = 4000 #fixed port
        self.dh = DiffieHellman()
        self.encryption_key = None
        # Pre-shared authentication key (in production, use proper key management)
        self.auth_key = b"server_secret_key"

    def authenticate_with_server(self, client_socket):
        """Respond to server's challenge for authentication."""
        challenge = client_socket.recv(1024).decode()
        response = hmac.new(self.auth_key, challenge.encode(), 
                          hashlib.sha256).digest()
        client_socket.send(response)

    def start(self):
        try:
            #Get server IP from user
            print("\n=== Secure Chat Client ===")
            self.host = input("Enter server IP address: ").strip()
            print(f"\nConnecting to server at {self.host}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            logger.info("Connected to server")

            try:
                # Authenticate with server
                self.authenticate_with_server(client_socket)

                # Exchange public keys
                server_public_key = int(client_socket.recv(1024).decode())
                client_socket.send(str(self.dh.public_key).encode())

                # Generate shared secret and derive encryption key
                shared_secret = self.dh.generate_shared_secret(server_public_key)
                salt = client_socket.recv(16)
                self.encryption_key = CryptoUtils.derive_key(shared_secret, salt)

                # Send test messages
                self.handle_user_input(client_socket)

            except Exception as e:
                logger.error(f"Communication error: {e}")
            finally:
                client_socket.close()

        except Exception as e:
            logger.error(f"Client error: {e}")

    def handle_user_input(self, client_socket):
        print("\nChat started. Type 'quit' to exit.")
        while True:
            try:
                # Get user input for message
                message = input("\nEnter your message: ")
                
                # Check if user wants to quit
                if message.lower() == 'quit':
                    logger.info("Chat ended by user")
                    break

                logger.info(f"Sending: {message}")

                # Encrypt message
                encrypted_message, mac = CryptoUtils.encrypt_message(
                    self.encryption_key, message
                )
                
                # Prepare message data with MAC
                message_data = {
                    'message': base64.b64encode(encrypted_message).decode(),
                    'mac': base64.b64encode(mac).decode()
                }
                client_socket.send(json.dumps(message_data).encode())

                # Receive and decrypt response
                response_data = json.loads(client_socket.recv(4096).decode())
                encrypted_response = base64.b64decode(response_data['message'])
                response_mac = base64.b64decode(response_data['mac'])

                decrypted_response = CryptoUtils.decrypt_message(
                    self.encryption_key, encrypted_response, response_mac
                )
                print(f"Server response: {decrypted_response}")

            except Exception as e:
                logger.error(f"Error in communication: {e}")
                break


if __name__ == "__main__":
    client = SecureClient()
    client.start()