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
    def __init__(self, host='localhost', port=4000):
        self.host = host
        self.port = port
        self.dh = DiffieHellman()
        print("Listening at 4000.")
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
                self.send_messages(client_socket)

            except Exception as e:
                logger.error(f"Communication error: {e}")
            finally:
                client_socket.close()

        except Exception as e:
            logger.error(f"Client error: {e}")

    def send_messages(self, client_socket):
        for i in range(3):
            try:
                message = f"Test message {i+1}"
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
                logger.info(f"Received: {decrypted_response}")

            except Exception as e:
                logger.error(f"Error sending message: {e}")
                break

if __name__ == "__main__":
    client = SecureClient()
    client.start()