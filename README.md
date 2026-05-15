# Post-Quantum Cryptography: ML-KEM (Kyber) Implementation
**Authors:** Binyamin Butolin, Ilan Merkovich  
**Course:** Cyber Security  
**Academic Year:** 2026

## 1. Project Overview
This project provides a functional implementation of the **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), formerly known as **Kyber**. It is designed to be secure against quantum adversaries by relying on the computational hardness of the **Module Learning With Errors (M-LWE)** problem.

The implementation covers the full cryptographic lifecycle:
* **Key Generation:** Creating a public lattice and a secret vector.
* **Encapsulation:** Encrypting arbitrary string messages into quantum-resistant ciphertexts.
* **Decapsulation:** Recovering the original plaintext using noise-cancellation mathematics.

## 2. Features
* **Custom Core Logic:** The M-LWE math is implemented from scratch using matrix operations.
* **Arbitrary Message Support:** Capable of encrypting strings, not just single bits.
* **Security Test Suite:** Includes automated negative tests for tampering and invalid keys.
* **Performance Benchmarking:** Reports execution time and data expansion factors.

## 3. Installation & Requirements
The project is written in **Python 3.x**. 

### Prerequisites
You need the `numpy` library for matrix mathematics:
```bash
pip install numpy
