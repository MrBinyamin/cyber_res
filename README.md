# Post-Quantum Cryptography: ML-KEM (Kyber) Implementation
**Author:** Binyamin Butolin  
**Course:** Cyber Security  
**Academic Year:** 2026

## 1. Project Overview
This project provides a functional implementation of the **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), formerly known as **Kyber**. [cite_start]It is designed to be secure against quantum adversaries by relying on the computational hardness of the **Module Learning With Errors (M-LWE)** problem[cite: 25, 28, 52].

The implementation covers the full cryptographic lifecycle:
* [cite_start]**Key Generation:** Creating a public lattice and a secret vector[cite: 58].
* [cite_start]**Encapsulation:** Encrypting arbitrary string messages into quantum-resistant ciphertexts[cite: 58].
* [cite_start]**Decapsulation:** Recovering the original plaintext using noise-cancellation mathematics[cite: 58].

## 2. Features
* [cite_start]**Custom Core Logic:** The M-LWE math is implemented from scratch using matrix operations[cite: 62].
* [cite_start]**Arbitrary Message Support:** Capable of encrypting strings, not just single bits[cite: 60].
* [cite_start]**Security Test Suite:** Includes automated negative tests for tampering and invalid keys.
* [cite_start]**Performance Benchmarking:** Reports execution time and data expansion factors[cite: 72].

## 3. Installation & Requirements
[cite_start]The project is written in **Python 3.x**[cite: 61]. 

### Prerequisites
You need the `numpy` library for matrix mathematics:
```bash
pip install numpy
