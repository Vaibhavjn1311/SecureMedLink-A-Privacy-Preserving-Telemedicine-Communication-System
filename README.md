# Cryptographic Authentication Performance Evaluation

## Overview
This project implements an authentication protocol between doctors and patients using ElGamal encryption, digital signatures, and AES encryption for secure communication. The authentication process includes key generation, encryption and decryption, signing, and verification to establish secure communication channels.

## Cryptographic Utilities
The system leverages the following cryptographic primitives:

- **Large Prime Generation** (256-bit)
- **ElGamal Encryption & Decryption**
- **ElGamal Signature Generation & Verification**
- **AES Encryption & Decryption** (AES-256, CBC mode)
- **SHA256 Hash Function**

## Performance Analysis
Each cryptographic primitive's execution time is critical to assess the overall performance and efficiency of the authentication system. The evaluation performed for different primitives with varying numbers of patients connected yielded the following results:

| Primitive                   | 1 Patient (seconds) | 2 Patients (seconds) | 3 Patients (seconds) | 4 Patients (seconds) |
|-----------------------------|---------------------|----------------------|----------------------|----------------------|
| Key Generation              | 0.003225            | 0.014510             | 0.025910             | 0.012343             |
| ElGamal Encryption          | 0.000250*           | 0.000203             | 0.000224             | 0.000203             |
| ElGamal Decryption          | 0.000170            | 0.000140             | 0.000130             | 0.000120             |
| ElGamal Signature           | 0.000165            | 0.000148             | 0.000153             | 0.000150             |
| ElGamal Verification        | 0.000290            | 0.000321             | 0.000361             | 0.000340             |
| AES Encryption              | 0.000045            | 0.000269             | 0.000224             | 0.000224             |
| AES Decryption              | 0.000110            | 0.000087             | 0.000065             | 0.000060             |

*(Note: The provided values are extracted directly from the performance analysis conducted.)*

### How to Run the Project

- **Doctor Side:**
```bash
python doctor.py
```

- **Patient Side:**
```bash
python patient.py [doctor_host] [patient_id]
```
eg: patient.py 127.0.0.1 Patient1

### Dependencies
Ensure you have installed the required libraries:
```bash
pip install pycryptodome
```

## Usage
- Run `doctor.py` to initiate the doctor's server.
- Run one or multiple instances of `patient.py` to simulate patients connecting and authenticating with the doctor.

## Performance Analysis
Use the built-in `performance_analysis` method within `doctor.py` to evaluate and print execution times of cryptographic primitives to ensure authentication efficiency and reliability.


