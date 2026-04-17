# 🚩 Cryptography Archive

This directory contains my detailed writeups and methodologies for solving crypto challenges in picoCTF2026 competition 🔐

---

## 🛠️ Toolset

You need a mathematical and cryptographic environment (Ubuntu 22.04 LTS or WSL) with the following tools:

* 🐍 **Python 3 & PyCryptodome**: The standard library for cryptographic primitives (AES, RSA, ECC)
    ```bash
    pip install pycryptodome
    ```
* 🌿 **SageMath**: An open-source mathematics software system, essential for Lattice-based attacks (LLL), Coppersmith, and polynomial operations
    ```bash
    sudo apt install sagemath
    ```
    or you can also use this website: https://sagecell.sagemath.org/
  
* 🛠️ **FeatherDuster/RsaCTFTool**: Automated tools for identifying and exploiting weak RSA keys or known PRNG vulnerabilities
* 🔍 **ExifTool**: Used for extracting hidden metadata (Steganography) that might contain hidden keys or hints

---

## 🔍 Featured Investigations

| Challenge Name | Key Technique | Status |
| :--- | :--- | :--- |
| **Spicy AES** | Linear Cryptanalysis / SubBytes Bypass | ✅ Solved |
| **Not TRUe** | Lattice-based Attack / NTRU / LLL Algorithm | ✅ Solved |
| **Related Messages** | RSA Franklin-Reiter Related Message Attack | ✅ Solved |
| **Shared Secrets** | Diffie-Hellman Key Exchange / Weak Secret Leak | ✅ Solved |
| **Small Trouble** | RSA Wiener's Attack / Continued Fractions | ✅ Solved |
| **StegoRSA** | Metadata Forensic / RSA Private Key Recovery | ✅ Solved |
| **Timestamped Secret**| PRNG Brute-force / SHA-256 Seed Prediction | ✅ Solved |
| **cryptomaze** | AES-128 / LFSR State Recovery | ✅ Solved |
| **shift registers** | LFSR Brute-force / Small State Space (8-bit) | ✅ Solved |

---

## ⚠️ Disclaimer
*Writeups are published only after the respective competitions have ended. Original flags are redacted to maintain the educational integrity of the challenges. 🛡️*
