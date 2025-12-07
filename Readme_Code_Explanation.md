# Code Analysis and Explanation

This document provides a technical breakdown of the two distinct programs included in this repository: a C++ mathematical implementation of Willans' Formula and a Python script for SSL Certificate analysis.

---

## Part 1: C++ Implementation (Willans' Formula)

This code calculates the $n$-th prime number using a formulaic approach derived from Wilson's Theorem, rather than standard sieving methods.

### Class: `PrimeComputer`
This class encapsulates the mathematical functions required for the formula.

#### 1. `factorial(int k)`
* **Syntax:** Standard iterative factorial calculation.
* **Data Flow:** Uses `unsigned long long` to store results.
* **Limitation:** It fits results up to $20!$. Anything larger causes integer overflow, which restricts this program to finding only small primes ($n \le 4$).

#### 2. `F(int j)` (The Prime Detector)
* **Purpose:** Returns `1` if $j$ is prime, and `0` if composite.
* **Logic:**
    1.  Calculates the argument $\frac{(j-1)! + 1}{j}$.
    2.  **Wilson's Theorem** states this is an integer only if $j$ is prime.
    3.  Applies Cosine: $\cos(\pi \times \text{argument})$.
        * **If Prime:** The argument is integer $\to \cos$ is $\pm 1 \to \text{squared is } 1$.
        * **If Composite:** The argument is fractional $\to \cos^2 < 1$.
    4.  **`floor()`:** Truncates the decimal, converting primes to `1` and composites to `0`.

#### 3. `getNthPrime(int n)`
* **The Loop:** Iterates from $i=1$ to $2^n$ (the theoretical upper bound).
* **`current_S_i`:** A cumulative counter. It sums the return values of `F(j)`. At any point `i`, this variable holds the count of how many primes have been found so far.
* **The Accumulator (`total_sum`):**
    * Calculates `pow(n / current_S_i, 1.0/n)`.
    * **Logic:** As long as the count of primes (`S_i`) is less than the target `n`, this division yields a number $\ge 1$.
    * The `floor` operation turns this into a binary switch (1 or 0), which is added to `total_sum`.

### `main()` Execution
1.  Instantiates `PrimeComputer`.
2.  Loops through test values 1, 2, 3, and 4.
3.  **Output:** Prints the prime number.
4.  **Constraint:** Explicitly warns that $n \ge 5$ fails because the formula requires $(2^n - 1)!$, causing a 64-bit integer overflow.

---

## Part 2: Python Implementation (Certificate Analyzer)

This script connects to a website, downloads its SSL/TLS certificate, and inspects the internal mathematics of its public key (specifically checking for Elliptic Curves).

### Global Data: `CURVE_REGISTRY`
* **Purpose:** A dictionary acting as a manual database.
* **Function:** Maps the **OID** (Object Identifier string, e.g., `'secp256r1'`) found in certificates to the actual mathematical parameters (Equation, Field Prime $p$) for display purposes.

### Class: `CertificateExtractor`
Handles raw networking and socket manipulation.

* **`clean_hostname(url)`**: Uses Regex to strip `https://` and pathing, ensuring only the domain remains.
* **`get_certificate(hostname)`**:
    * **`socket.create_connection`**: Opens a TCP connection to port 443.
    * **`context.wrap_socket`**: Upgrades TCP to TLS (Transport Layer Security) by performing the handshake.
    * **`getpeercert(binary_form=True)`**: Extracts the server's certificate in **DER** format (raw binary).
* **`save_to_file`**: Writes the binary bytes to a local `.cer` file.

### Class: `CertificateAnalyzer`
Parses the binary data using the `cryptography` library.

* **`__init__`**: Loads the X.509 object from DER data.
* **`analyze_public_key`**:
    * Calls `self.cert.public_key()`.
    * **Type Checking (`isinstance`):**
        * **If ECC:** Extracts the curve name, looks it up in `CURVE_REGISTRY`, and prints math details.
        * **If RSA:** Extracts and prints the Key Size, Modulus ($n$), and Exponent ($e$).

### `main` Execution Flow
1.  **Input:** User enters a URL.
2.  **Clean:** URL is sanitized.
3.  **Network:** Script connects and retrieves raw bytes.
4.  **I/O:** Saves the raw certificate to disk.
5.  **Analysis:** Parses the bytes and prints the cryptographic report.

---

## Libraries Used

| Language | Library | Purpose |
| :--- | :--- | :--- |
| **C++** | `<cmath>` | Used for `cos`, `pow`, `floor`, and `M_PI`. |
| **C++** | `<iostream>` | Standard Input/Output streams. |
| **Python** | `ssl` / `socket` | Low-level networking to perform TLS handshakes. |
| **Python** | `cryptography` | Parses X.509 binary structures to extract keys. |