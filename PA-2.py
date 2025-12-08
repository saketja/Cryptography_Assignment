import ssl
import socket
import re
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# --- Database of Standard Curves (Reference Parameters) ---
CURVE_REGISTRY = {
    'secp256r1': {
        "common_name": "NIST P-256",
        "equation": "y^2 = x^3 - 3x + b (mod p)",
        "p": "2^256 - 2^224 + 2^192 + 2^96 - 1",
        "p_hex": "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "b_hex": "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
    },
    'secp384r1': {
        "common_name": "NIST P-384",
        "equation": "y^2 = x^3 - 3x + b (mod p)",
        "p": "2^384 - 2^128 - 2^96 + 2^32 - 1",
        "p_hex": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "b_hex": "B3312FA7E23EE7E4988E056B3CC62A6D5DF525228BD418F6719F119CE7430C354765961B2C07D7B060002A1647573623"
    }
}

# ------------------------------------------------------------
# 1) Certificate Extractor (Networking + File Saving)
# ------------------------------------------------------------
class CertificateExtractor:

    @staticmethod
    def clean_hostname(url):
        """Remove http://, https://, and path segments."""
        return re.sub(r'(^https?://)|(/.*$)', '', url)

    @staticmethod
    def get_certificate(hostname, port=443):
        print(f"[*] Connecting to {hostname}:{port} ...")

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(binary_form=True)

        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    @staticmethod
    def save_to_file(der_data, filename="certificate.cer"):
        with open(filename, "wb") as f:
            f.write(der_data)
        print(f"[*] Saved certificate → {filename}")


# ------------------------------------------------------------
# 2) Certificate Analyzer (X.509 Parsing + ECC Extraction)
# ------------------------------------------------------------
class CertificateAnalyzer:

    def __init__(self, der_data):
        self.cert = x509.load_der_x509_certificate(der_data)

    def print_general_info(self):
        print("\n--- General Certificate Information ---")
        print(f"Subject:      {self.cert.subject.rfc4514_string()}")
        print(f"Issuer:       {self.cert.issuer.rfc4514_string()}")
        print(f"Valid From:   {self.cert.not_valid_before}")
        print(f"Valid Until:  {self.cert.not_valid_after}")

    def analyze_public_key(self):
        print("\n--- Cryptographic Parameters ---")
        pub_key = self.cert.public_key()

        # Case A: ECC Public Key
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            print("[TYPE] Elliptic Curve Digital Signature Algorithm (ECDSA)")

            curve = pub_key.curve
            curve_name = getattr(curve, "name", None)

            print(f"Curve Used: {curve_name}")

            if curve_name in CURVE_REGISTRY:
                details = CURVE_REGISTRY[curve_name]
                print(f"\n>> Mathematical Details for {details['common_name']}:")
                print(f"  Equation: {details['equation']}")
                print(f"  Field Prime (p): {details['p']}")
                print(f"  Hex(p): {details['p_hex'][:60]}...")
            else:
                print(">> Curve parameters not found in local registry.")

        # Case B: RSA Public Key
        elif isinstance(pub_key, rsa.RSAPublicKey):
            print("[TYPE] RSA (Not ECC)")
            nums = pub_key.public_numbers()
            print(f"Key Size: {pub_key.key_size} bits")
            print(f"Exponent (e): {nums.e}")
            print(f"Modulus (n): {str(nums.n)[:60]}...")
            print("\n[NOTE] This website does NOT use Elliptic Curve Cryptography.")

        else:
            print("[ERROR] Unknown Public Key Type:", type(pub_key))


# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------
if __name__ == "__main__":
    url = input("Enter website (e.g., google.com or https://www.bits-pilani.ac.in): ").strip()
    hostname = CertificateExtractor.clean_hostname(url)

    raw = CertificateExtractor.get_certificate(hostname)

    if raw:
        CertificateExtractor.save_to_file(raw, f"{hostname}.cer")
        analyzer = CertificateAnalyzer(raw)
        analyzer.print_general_info()
        analyzer.analyze_public_key()
