import socket
import json
import time
import random
import sys
import select
import threading
import os
import crypto_utils

class Patient:
    def __init__(self, doctor_host, doctor_port, patient_id):
        self.doctor_host = doctor_host
        self.doctor_port = doctor_port
        self.ID = patient_id
        self.delta_ts = 5
        # Load doctor's public key from file
        self.doctor_public = self.load_doctor_public()
        self.p = self.doctor_public["p"]
        self.g = self.doctor_public["g"]
        self.doctor_id = self.doctor_public["ID"]
        # Generate patient key pair
        self.x, self.y = crypto_utils.generate_keys(self.p, self.g)
        # For simulation, session key is a random integer
        self.session_key = random.randint(100000, 999999)
        self.TSi = None
        self.TSGWN = None
        self.TS_prime = None
        self.RNi = None
        self.RNGWN = None
        self.group_key = None
        self.sock = None
        self.running = True

    def load_doctor_public(self):
        with open("doctor_public.json", "r") as f:
            data = json.load(f)
        return data

    def connect_to_doctor(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.doctor_host, self.doctor_port))
        self.reader = self.sock.makefile('r')
        print(f"{self.ID}: Connected to doctor at {self.doctor_host}:{self.doctor_port}")

    def create_auth_request(self):
        self.TSi = time.time()
        self.RNi = random.randint(1000, 9999)
        auth_request = {}
        auth_request["TSi"] = self.TSi
        auth_request["RNi"] = self.RNi
        auth_request["IDGWN"] = self.doctor_id
        auth_request["EKUGWN"] = crypto_utils.elgamal_encrypt(self.doctor_public["p"], self.g, self.doctor_public["y"], self.session_key)
        ekugwn_str = json.dumps(auth_request["EKUGWN"], separators=(',',':'))
        message = str(self.TSi) + str(self.RNi) + self.doctor_id + ekugwn_str
        auth_request["SignData1"] = crypto_utils.elgamal_sign(self.p, self.g, self.x, message)
        auth_request["patient_id"] = self.ID
        auth_request["patient_public"] = (self.p, self.g, self.y)
        print(f"{self.ID}: Sending authentication request.")
        return auth_request

    def send_auth_request(self):
        auth_request = self.create_auth_request()
        self.sock.sendall((json.dumps(auth_request) + "\n").encode())

    def process_response(self, response):
        current_time = time.time()
        TSGWN = response["TSGWN"]
        if abs(current_time - TSGWN) > self.delta_ts:
            print(f"{self.ID}: Timestamp verification failed in response.")
            return False
        if response["IDDi"] != self.ID:
            print(f"{self.ID}: Response ID mismatch.")
            return False
        ciphertext = tuple(int(x) for x in response["EKUDi"])
        decrypted_session_key = crypto_utils.elgamal_decrypt(self.p, self.x, ciphertext)
        print(f"{self.ID}: Original session key: {self.session_key}, decrypted: {decrypted_session_key}")
        if decrypted_session_key != self.session_key:
            print(f"{self.ID}: Session key mismatch!")
            return False
        else:
            print(f"{self.ID}: Received and verified session key from doctor.")
        self.TSGWN = TSGWN
        self.RNGWN = response["RNGWN"]
        return True

    def send_session_key_verifier(self):
        SK = crypto_utils.hash_function(self.session_key, self.TSi, self.TSGWN, self.RNi, self.RNGWN, self.ID, self.doctor_id)
        self.TS_prime = time.time()
        SK_verifier = crypto_utils.hash_function(SK, self.TS_prime)
        msg = {
            "patient_id": self.ID,
            "TS_prime": self.TS_prime,
            "SKVDi_GWN": SK_verifier
        }
        print(f"{self.ID}: Sending session key verifier.")
        self.sock.sendall((json.dumps(msg) + "\n").encode())

    def listen_for_messages(self):
        while self.running:
            try:
                msg_json = self.reader.readline().strip()
                if not msg_json:
                    break
                msg = json.loads(msg_json)
                opcode = msg.get("opcode")
                if opcode == 60:
                    print(f"{self.ID}: Disconnected by doctor.")
                    self.running = False
                    break
                elif opcode == 70:  # Direct message
                    encrypted_message = bytes.fromhex(msg["encrypted_message"])
                    aes_key = crypto_utils.hash_function(self.session_key).encode()[:32]
                    decrypted_message = crypto_utils.aes_decrypt(aes_key, encrypted_message)
                    print(f"\n{self.ID}: Received direct message: {decrypted_message.decode()}")
                elif opcode == 30:  # Group key message
                    encrypted_group_key = bytes.fromhex(msg["encrypted_group_key"])
                    aes_key = crypto_utils.hash_function(self.session_key).encode()[:32]
                    self.group_key = crypto_utils.aes_decrypt(aes_key, encrypted_group_key)
                    print(f"{self.ID}: Received updated group key.")
                elif opcode == 40:  # Broadcast message
                    encrypted_message = bytes.fromhex(msg["encrypted_message"])
                    if self.group_key is None:
                        print(f"{self.ID}: No group key, cannot decrypt broadcast.")
                    else:
                        decrypted_message = crypto_utils.aes_decrypt(self.group_key, encrypted_message)
                        print(f"\n{self.ID}: Received broadcast message: {decrypted_message.decode()}")
                else:
                    print(f"{self.ID}: Unknown message received: {msg}")
            except Exception as e:
                print(f"{self.ID}: Error in listening thread: {e}")
                break

    def send_message_to_doctor(self, message):
        aes_key = crypto_utils.hash_function(self.session_key).encode()[:32]
        encrypted_message = crypto_utils.aes_encrypt(aes_key, message.encode())
        msg = {"opcode": 50, "encrypted_message": encrypted_message.hex()}
        self.sock.sendall((json.dumps(msg) + "\n").encode())

    def interactive_chat(self):
        print(f"{self.ID}: Starting interactive chat with doctor. Type 'q' to quit.")
        while self.running:
            # Wait up to 1 second for input from sys.stdin.
            rlist, _, _ = select.select([sys.stdin], [], [], 1.0)
            # If self.running was set to False (by the listener thread after a disconnect), break out.
            if not self.running:
                break
            # Only show prompt if there's user input.
            if rlist:
                # Print prompt and read the input.
                print(f"{self.ID} - Enter message to doctor: ", end="", flush=True)
                message = sys.stdin.readline().strip()
                if message.lower() == 'q':
                    self.running = False
                    disconnect_msg = {"opcode": 60}
                    self.sock.sendall((json.dumps(disconnect_msg) + "\n").encode())
                    break
                self.send_message_to_doctor(message)
        print(f"{self.ID}: Chat ended.")

    def run(self):
        self.connect_to_doctor()
        self.send_auth_request()
        response_json = self.reader.readline().strip()
        if not response_json:
            print(f"{self.ID}: No response from doctor.")
            return
        response = json.loads(response_json)
        if not self.process_response(response):
            return
        self.send_session_key_verifier()
        # Do not block waiting for group key; let listener thread update it if/when it arrives.
        listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        listener_thread.start()
        self.interactive_chat()
        self.sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 patient.py <doctor_host> <patient_id>")
        sys.exit(1)
    doctor_host = sys.argv[1]
    patient_id = sys.argv[2]
    doctor_port = 8000
    patient_instance = Patient(doctor_host, doctor_port, patient_id)
    patient_instance.run()
