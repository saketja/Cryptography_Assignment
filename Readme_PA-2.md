# Cryptography_Assignment
# PA-2: SSL/TLS Certificate Inspector & Parameter Extractor

## 📌 Project Overview
This tool is a robust cryptographic inspection script designed to establish a secure handshake with any HTTPS-enabled website, download its X.509 security certificate, and analyze its public key algorithms.

While the primary goal of this assignment is to extract **Elliptic Curve Cryptography (ECC)** parameters (Equation & Field Characteristic), this tool is generalized to handle **RSA** and other algorithms gracefully.

## 🚀 Features
* **Universal Input Handling:** Intelligent regex parsing allows inputting URLs in any format (e.g., `https://google.com`, `www.google.com`, or `google.com/search`).
* **Dual-Mode Analysis:**
    * **ECC Mode:** Detects OIDs (e.g., `secp256r1`), extracts the Curve Name, and maps it to the underlying mathematical equation and prime field characteristic ($p$).
    * **RSA Mode:** Detects RSA certificates (common in university websites) and extracts Key Size, Modulus ($n$), and Public Exponent ($e$).
* **Packet Extraction:** Automatically downloads and saves the raw binary certificate (DER format) to the local disk (`.cer` file) for independent verification.
* **Modular Design:** Separates network logic (`CertificateExtractor`) from cryptographic parsing (`CertificateAnalyzer`).

## 🛠️ Prerequisites
* **Python 3.6+**
* **Cryptography Library**

### Installation
Install the required dependency using pip:
```bash
pip install cryptography

### Usage
Compile and run the `PA-2.py` file:
````text
```bash
python PA-2.py