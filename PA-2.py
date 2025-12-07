import ssl
import socket
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# --- Database of Standard Curves (The "Reference" Book) ---
# Certificates send a "Name" (OID), not the equation. 
# We must look up the math parameters based on that name.
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

class CertificateExtractor:
    """Module responsible for Network Connections and Raw Extraction"""
    
    @staticmethod
    def clean_hostname(url):
        # Removes http://, https://, and trailing slashes
        return re.sub(r'(^https?://)|(/.*$)', '', url)

    @staticmethod
    def get_certificate(hostname, port=443):
        print(f"[*] Connecting to {hostname} on port {port}...")
        try:
            # Create a socket connection
            context = ssl.create_default_context()
            # We wrap the socket to perform the TLS Handshake
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # This retrieves the binary certificate (DER format)
                    der_cert = ssock.getpeercert(binary_form=True)
            return der_cert
        except socket.gaierror:
            print(f"[!] Error: Could not resolve hostname '{hostname}'. Check spelling.")
        except ConnectionRefusedError:
            print(f"[!] Error: Connection refused by {hostname}.")
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")
        return None

    @staticmethod
    def save_to_file(der_data, filename="extracted_cert.cer"):
        """Saves the raw packet data to disk"""
        with open(filename, "wb") as f:
            f.write(der_data)
        print(f"[*] Raw certificate saved to '{filename}'")

class CertificateAnalyzer:
    """Module responsible for Cryptographic Parsing"""

    def __init__(self, der_data):
        self.cert = x509.load_der_x509_certificate(der_data, default_backend())

    def print_general_info(self):
        print("\n--- General Certificate Info ---")
        # Extract Subject (Who owns it) and Issuer (Who signed it)
        subject = self.cert.subject.rfc4514_string()
        issuer = self.cert.issuer.rfc4514_string()
        print(f"Subject: {subject}")
        print(f"Issuer:  {issuer}")
        print(f"Valid From: {self.cert.not_valid_before_utc}")
        print(f"Valid To:   {self.cert.not_valid_after_utc}")

    def analyze_public_key(self):
        pub_key = self.cert.public_key()
        print("\n--- Cryptographic Parameters ---")

        # Scenario A: Elliptic Curve (The Assignment Goal)
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            curve_oid = pub_key.curve.name
            print(f"[TYPE] Elliptic Curve Cryptography (ECC)")
            print(f"[OID]  {curve_oid}")
            
            # Look up the math details
            details = CURVE_REGISTRY.get(curve_oid)
            if details:
                print(f"\n>> Mathematical Extraction for {details['common_name']}:")
                print(f"   Equation: {details['equation']}")
                print(f"   Field Prime (p): {details['p']}")
                print(f"   Hex Dump (p): {details['p_hex'][:40]}... (truncated)")
            else:
                print(f">> Parameters for {curve_oid} are not in the local registry.")

        # Scenario B: RSA (Like BITS Website)
        elif isinstance(pub_key, rsa.RSAPublicKey):
            print(f"[TYPE] RSA (Rivest–Shamir–Adleman)")
            print(f"   Key Size: {pub_key.key_size} bits")
            print(f"   Public Exponent (e): {pub_key.public_numbers().e}")
            print(f"   Modulus (n): {str(pub_key.public_numbers().n)[:40]}... (truncated)")
            print("\n[NOTE] This website does NOT use Elliptic Curves.")
        
        else:
            print(f"[TYPE] Unknown Algorithm: {type(pub_key)}")

# --- Main Driver Code ---
if __name__ == "__main__":
    user_input = input("Enter website (e.g., google.com, bits-pilani.ac.in): ").strip()
    
    # 1. Clean Input
    target_host = CertificateExtractor.clean_hostname(user_input)
    
    if target_host:
        # 2. Extract Packet
        raw_cert = CertificateExtractor.get_certificate(target_host)
        
        if raw_cert:
            # 3. Save Packet (Actually extracting the file)
            CertificateExtractor.save_to_file(raw_cert, f"{target_host}.cer")
            
            # 4. Analyze Packet
            analyzer = CertificateAnalyzer(raw_cert)
            analyzer.print_general_info()
            analyzer.analyze_public_key()