import socket
import threading
import json
import time
import random
import sys
import select
import crypto_utils

class Doctor:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        # Phase 1: Key Generation
        self.p = crypto_utils.generate_large_prime(256)
        self.g = 2
        self.x, self.y = crypto_utils.generate_keys(self.p, self.g)
        self.ID = "Doctor"
        self.sessions = {}               # patient_id -> session info
        self.authenticated_patients = {} # patient_id -> session_key
        self.patient_connections = {}    # patient_id -> socket
        self.lock = threading.Lock()
        self.delta_ts = 5              # max transmission delay (seconds)
        self.group_key = None          # shared group key (computed once)
        self.server_running = True

        # New attributes for dynamic broadcast management:
        self.broadcast_in_progress = False
        self.current_broadcast_group = set()  # IDs included in current broadcast session
        self.pending_patients = {}            # patient_id -> socket for patients joining mid-broadcast
        self.threshold_new = 4                # x: minimum new members to trigger a new broadcast
        self.last_broadcast_count = 0         # record count of patients in previous broadcast session

    def save_public_key(self):
        """Save doctor's public parameters to a file for patients."""
        data = {"p": self.p, "g": self.g, "y": self.y, "ID": self.ID}
        with open("doctor_public.json", "w") as f:
            json.dump(data, f)
        print("Doctor public key saved to doctor_public.json.")

    def handle_patient(self, conn, addr):
        try:
            reader = conn.makefile('r')
            # 1. Receive authentication request
            auth_request_json = reader.readline().strip()
            if not auth_request_json:
                conn.close()
                return
            auth_request = json.loads(auth_request_json)
            response = self.receive_auth_request(auth_request)
            if response is None:
                conn.close()
                return
            # Send authentication response (opcode 20)
            conn.sendall((json.dumps(response) + "\n").encode())
            # 2. Receive session key verifier (opcode 10)
            verifier_json = reader.readline().strip()
            if not verifier_json:
                conn.close()
                return
            verifier_msg = json.loads(verifier_json)
            valid = self.process_session_key_verifier(verifier_msg)
            if not valid:
                conn.close()
                return
            # Save connection and decide on group key delivery.
            with self.lock:
                self.patient_connections[auth_request["patient_id"]] = conn
                # If a broadcast is in progress, add patient to pending queue.
                if self.broadcast_in_progress:
                    self.pending_patients[auth_request["patient_id"]] = conn
                    print(f"{auth_request['patient_id']} added to pending for next broadcast session.")
                else:
                    # If no broadcast is running and a group key exists, send it immediately.
                    if self.group_key is not None:
                        group_key_msg = self.send_group_key(auth_request["patient_id"])
                        conn.sendall((json.dumps(group_key_msg) + "\n").encode())
            # 3. Listen for further messages from patient
            while True:
                msg_json = reader.readline().strip()
                if not msg_json:
                    break
                msg = json.loads(msg_json)
                opcode = msg.get("opcode")
                if opcode == 60:
                    print(f"Patient {auth_request['patient_id']} requested disconnect.")
                    break
                elif opcode == 50:
                    session_key = self.authenticated_patients.get(auth_request["patient_id"])
                    if session_key is None:
                        print("No session key for patient", auth_request["patient_id"])
                        continue
                    aes_key = crypto_utils.hash_function(session_key).encode()[:32]
                    try:
                        ciphertext = bytes.fromhex(msg["encrypted_message"])
                        decrypted_message = crypto_utils.aes_decrypt(aes_key, ciphertext)
                        msg_text = decrypted_message.decode()
                        print(f"\n[Incoming from {auth_request['patient_id']}]: {msg_text}")
                    except Exception as e:
                        print("Failed to decrypt message from", auth_request["patient_id"], ":", e)
                else:
                    print("Received unknown message from", auth_request["patient_id"], msg)
        except Exception as e:
            print("Error handling patient:", e)
        finally:
            conn.close()
            with self.lock:
                if auth_request["patient_id"] in self.patient_connections:
                    del self.patient_connections[auth_request["patient_id"]]
                if auth_request["patient_id"] in self.pending_patients:
                    del self.pending_patients[auth_request["patient_id"]]
            print(f"Connection with {auth_request['patient_id']} closed.")

    def receive_auth_request(self, auth_request):
        current_time = time.time()
        TSi = auth_request["TSi"]
        if abs(current_time - TSi) > self.delta_ts:
            print("Timestamp verification failed for patient", auth_request["patient_id"])
            return None
        if auth_request["IDGWN"] != self.ID:
            print("Doctor ID mismatch in auth request from", auth_request["patient_id"])
            return None
        # Verify signature using patient's public key.
        patient_pub = auth_request["patient_public"]  # (p, g, y)
        ekugwn_str = json.dumps(auth_request["EKUGWN"], separators=(',',':'))
        message = str(TSi) + str(auth_request["RNi"]) + auth_request["IDGWN"] + ekugwn_str
        signature = auth_request["SignData1"]
        valid = crypto_utils.elgamal_verify(patient_pub[0], self.g, patient_pub[2], message, tuple(signature))
        if not valid:
            print("Signature verification failed for patient", auth_request["patient_id"])
            return None
        # Decrypt session key from patient.
        ciphertext = tuple(int(x) for x in auth_request["EKUGWN"])
        session_key = crypto_utils.elgamal_decrypt(self.p, self.x, ciphertext)
        self.sessions[auth_request["patient_id"]] = {
            "TSi": TSi,
            "RNi": auth_request["RNi"],
            "session_key": session_key,
            "patient_public": patient_pub
        }
        print("Received and verified auth request from", auth_request["patient_id"])
        response = self.create_response(auth_request["patient_id"])
        return response

    def create_response(self, patient_id):
        session = self.sessions[patient_id]
        TSi = session["TSi"]
        RNi = session["RNi"]
        TSGWN = time.time()
        RNGWN = random.randint(1000, 9999)
        patient_pub = session["patient_public"]
        session_key = session["session_key"]
        EKUDi = crypto_utils.elgamal_encrypt(patient_pub[0], self.g, patient_pub[2], session_key)
        ekudi_str = json.dumps(EKUDi, separators=(',',':'))
        message = str(TSGWN) + str(RNGWN) + patient_id + ekudi_str
        signature = crypto_utils.elgamal_sign(self.p, self.g, self.x, message)
        session["TSGWN"] = TSGWN
        session["RNGWN"] = RNGWN
        response = {
            "opcode": 20,
            "TSGWN": TSGWN,
            "RNGWN": RNGWN,
            "IDDi": patient_id,
            "EKUDi": EKUDi,
            "SignData2": signature
        }
        print("Sending response to", patient_id)
        return response

    def process_session_key_verifier(self, verifier_msg):
        patient_id = verifier_msg["patient_id"]
        session = self.sessions.get(patient_id)
        if not session:
            print("No session found for patient", patient_id)
            return False
        current_time = time.time()
        TS_prime = verifier_msg["TS_prime"]
        if abs(current_time - TS_prime) > self.delta_ts:
            print("Timestamp verification failed in session key verifier for", patient_id)
            return False
        session_key = session["session_key"]
        TSi = session["TSi"]
        TSGWN = session["TSGWN"]
        RNi = session["RNi"]
        RNGWN = session["RNGWN"]
        computed_SK = crypto_utils.hash_function(session_key, TSi, TSGWN, RNi, RNGWN, patient_id, self.ID)
        computed_verifier = crypto_utils.hash_function(computed_SK, TS_prime)
        if computed_verifier == verifier_msg["SKVDi_GWN"]:
            print("Session key verified for", patient_id)
            self.authenticated_patients[patient_id] = session_key
            return True
        else:
            print("Session key verification failed for", patient_id)
            return False

    def compute_group_key(self, patient_ids=None):
        """Compute the shared group key using only the specified patient IDs.
           If patient_ids is None, use all authenticated patients.
           GK = h(SK_patient1 ∥ SK_patient2 ∥ ... ∥ doctor_secret_x)
        """
        if patient_ids is None:
            patient_ids = self.authenticated_patients.keys()
        if not patient_ids:
            print("No patients provided for computing group key")
            return None
        keys_concatenated = ""
        for pid in sorted(patient_ids):
            keys_concatenated += str(self.authenticated_patients[pid])
        keys_concatenated += str(self.x)
        group_key_hex = crypto_utils.hash_function(keys_concatenated)
        group_key = group_key_hex.encode()[:32]
        print("Group key computed for patients:", patient_ids)
        return group_key

    def send_group_key(self, patient_id):
        """Encrypt and send the shared group key using the patient's session key."""
        session_key = self.authenticated_patients.get(patient_id)
        if session_key is None:
            print("No session key for patient", patient_id)
            return None
        aes_key = crypto_utils.hash_function(session_key).encode()[:32]
        encrypted_group_key = crypto_utils.aes_encrypt(aes_key, self.group_key)
        msg = {
            "opcode": 30,
            "encrypted_group_key": encrypted_group_key.hex()
        }
        print("Sending group key to", patient_id)
        return msg

    def send_direct_message(self, patient_id, message):
        session_key = self.authenticated_patients.get(patient_id)
        if session_key is None:
            print("No session key for patient", patient_id)
            return
        aes_key = crypto_utils.hash_function(session_key).encode()[:32]
        encrypted_message = crypto_utils.aes_encrypt(aes_key, message.encode())
        direct_msg = {"opcode": 70, "encrypted_message": encrypted_message.hex()}
        with self.lock:
            conn = self.patient_connections.get(patient_id)
        if conn:
            try:
                conn.sendall((json.dumps(direct_msg) + "\n").encode())
                print("Sending direct message to", patient_id)
            except Exception as e:
                print("Failed to send direct message to", patient_id, ":", e)
        else:
            print("No connection found for patient", patient_id)

    def broadcast_message(self, message):
        """
        Modified broadcast_message:
         - Locks in the current broadcast group (only those patients who were connected
           at the time of broadcast initiation).
         - Sets a flag so new patients joining during the broadcast are queued.
         - After broadcast, checks pending patients:
             * If the number of pending patients >= threshold, rekey for all active patients.
             * Otherwise, for each pending patient, perform individual rekeying.
        """
        with self.lock:
            # Mark broadcast in progress.
            self.broadcast_in_progress = True
            # Capture current broadcast group (exclude any already pending).
            self.current_broadcast_group = set(self.patient_connections.keys()) - set(self.pending_patients.keys())
            self.last_broadcast_count = len(self.current_broadcast_group)
            print("Broadcast starting for patients:", self.current_broadcast_group)
            # Compute group key using only the current broadcast group.
            self.group_key = self.compute_group_key(patient_ids=self.current_broadcast_group)
            # Distribute the group key to current broadcast group.
            for pid in self.current_broadcast_group:
                group_key_msg = self.send_group_key(pid)
                try:
                    self.patient_connections[pid].sendall((json.dumps(group_key_msg) + "\n").encode())
                except Exception as e:
                    print("Failed to send group key to", pid, ":", e)
        # Encrypt and send the broadcast message using the current group key.
        encrypted_message = crypto_utils.aes_encrypt(self.group_key, message.encode())
        broadcast_msg = {
            "opcode": 40,
            "encrypted_message": encrypted_message.hex()
        }
        print("Broadcasting message to current group only.")
        with self.lock:
            for pid in self.current_broadcast_group:
                try:
                    self.patient_connections[pid].sendall((json.dumps(broadcast_msg) + "\n").encode())
                except Exception as e:
                    print("Failed to send broadcast to", pid, ":", e)
            # Mark broadcast as finished.
            self.broadcast_in_progress = False

            # Process pending patients (those who joined during broadcast)
            pending_count = len(self.pending_patients)
            if pending_count >= self.threshold_new:
                print("Initiating new broadcast session for pending patients.")
                # Recompute group key for ALL active patients (new broadcast group)
                new_group = set(self.patient_connections.keys())
                self.group_key = self.compute_group_key(patient_ids=new_group)
                for pid in new_group:
                    group_key_msg = self.send_group_key(pid)
                    try:
                        self.patient_connections[pid].sendall((json.dumps(group_key_msg) + "\n").encode())
                        print("Sent new group key to", pid)
                    except Exception as e:
                        print("Failed to send new group key to", pid, ":", e)
                self.pending_patients.clear()
                self.last_broadcast_count = len(new_group)
            else:
                # Not enough pending patients; process each one individually.
                for pid in list(self.pending_patients.keys()):
                    print("Processing new patient individually:", pid)
                    session_key = self.authenticated_patients.get(pid)
                    if session_key is None:
                        continue
                    new_group_key_hex = crypto_utils.hash_function(session_key, self.x)
                    new_group_key = new_group_key_hex.encode()[:32]
                    aes_key = crypto_utils.hash_function(session_key).encode()[:32]
                    encrypted_group_key = crypto_utils.aes_encrypt(aes_key, new_group_key)
                    msg_individual = {
                        "opcode": 30,
                        "encrypted_group_key": encrypted_group_key.hex()
                    }
                    try:
                        self.patient_connections[pid].sendall((json.dumps(msg_individual) + "\n").encode())
                        print("Sent individual new group key to", pid)
                    except Exception as e:
                        print("Failed to send individual new group key to", pid, ":", e)
                    del self.pending_patients[pid]

    def disconnect_all(self):
        disconnect_msg = {"opcode": 60}
        with self.lock:
            for pid, conn in list(self.patient_connections.items()):
                try:
                    # Send the disconnect message
                    conn.sendall((json.dumps(disconnect_msg) + "\n").encode())
                    # Shutdown the connection to ensure both sides know it's closing
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    print(f"Failed to disconnect patient {pid}: {e}")
                finally:
                    conn.close()
            self.patient_connections.clear()
        print("All patients disconnected.")

    def performance_analysis(self):
        import time
        metrics = {}
        start = time.perf_counter()
        p = crypto_utils.generate_large_prime(256)
        g = 2
        x, y = crypto_utils.generate_keys(p, g)
        end = time.perf_counter()
        metrics["Key Generation"] = end - start

        m = 123456789
        start = time.perf_counter()
        ciphertext = crypto_utils.elgamal_encrypt(p, g, y, m)
        end = time.perf_counter()
        metrics["ElGamal Encryption"] = end - start

        start = time.perf_counter()
        plaintext = crypto_utils.elgamal_decrypt(p, x, ciphertext)
        end = time.perf_counter()
        metrics["ElGamal Decryption"] = end - start

        message = "Test message"
        start = time.perf_counter()
        signature = crypto_utils.elgamal_sign(p, g, x, message)
        end = time.perf_counter()
        metrics["ElGamal Signature"] = end - start

        start = time.perf_counter()
        valid = crypto_utils.elgamal_verify(p, g, y, message, signature)
        end = time.perf_counter()
        metrics["ElGamal Verification"] = end - start

        key = crypto_utils.hash_function("test").encode()[:32]
        plaintext_bytes = b"This is a test message."
        start = time.perf_counter()
        aes_ct = crypto_utils.aes_encrypt(key, plaintext_bytes)
        end = time.perf_counter()
        metrics["AES Encryption"] = end - start

        start = time.perf_counter()
        aes_pt = crypto_utils.aes_decrypt(key, aes_ct)
        end = time.perf_counter()
        metrics["AES Decryption"] = end - start

        print("\nPerformance Analysis:")
        for k, v in metrics.items():
            print(f"{k}: {v:.6f} seconds")
        return metrics

    def interactive_menu(self):
        print("\n--- Doctor Interactive Menu ---")
        while True:
            print("\nOptions:")
            print("  d - Send a direct message to a patient")
            print("  b - Broadcast a message to all patients")
            print("  q - Quit, disconnect all patients, and shutdown server")
            choice = input("Enter your choice (d/b/q): ").strip().lower()
            if choice == 'd':
                pid = input("Enter patient ID: ").strip()
                message = input("Enter your direct message: ")
                self.send_direct_message(pid, message)
            elif choice == 'b':
                message = input("Enter broadcast message: ")
                self.broadcast_message(message)
            elif choice == 'q':
                print("Shutting down server.")
                # Optionally notify patients that the server is shutting down
                self.broadcast_message("Server is shutting down. Disconnecting...")
                self.disconnect_all()
                self.server_running = False
                self.performance_analysis()
                break
            else:
                print("Invalid option, try again.")

    def run(self):
        self.save_public_key()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        # Set a timeout so accept() doesn't block indefinitely.
        server_socket.settimeout(1.0)
        print("Doctor server listening on {}:{}".format(self.host, self.port))
        menu_thread = threading.Thread(target=self.interactive_menu, daemon=True)
        menu_thread.start()
        try:
            while self.server_running:
                try:
                    conn, addr = server_socket.accept()
                except socket.timeout:
                    continue
                print("Accepted connection from", addr)
                threading.Thread(target=self.handle_patient, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("KeyboardInterrupt received. Shutting down server.")
        finally:
            server_socket.close()
        print("Server shutdown complete.")


if __name__ == "__main__":
    doc = Doctor()
    doc.run()
