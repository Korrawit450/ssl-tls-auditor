import sys
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

def parse_hostname(target: str) -> str:
    """URL Only Hostname/Domain"""
    if "://" in target:
        target = urlparse(target).netloc
    return target.split(":")[0].strip()

def check_ssl_certificate(hostname: str, port: int = 443):
    print(f"\n{Fore.CYAN}=== SSL/TLS Certificate Audit: {hostname} ==={Style.RESET_ALL}\n")
    
    # 1. ตรวจสอบรายละเอียดใบรับรอง
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        print(f"{Fore.RED}[!] Certificate Verification Failed: {e.reason}{Style.RESET_ALL}")
        return
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        print(f"{Fore.RED}[!] Connection Error: {e}{Style.RESET_ALL}")
        return

    # วันหมดอายุ
    not_after_str = cert.get("notAfter")
    expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
    days_left = (expiry_date - datetime.utcnow()).days

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", []))
    common_name = issuer.get("commonName", "Unknown")
    org_name = issuer.get("organizationName", "Unknown")

    print(f"{Fore.GREEN}[+] Connection Established:{Style.RESET_ALL}")
    print(f"    Active Protocol  : {Fore.YELLOW}{protocol_version}{Style.RESET_ALL}")
    print(f"    Cipher Suite     : {cipher[0]} ({cipher[2]} bits)")
    print(f"    Issuer           : {org_name} ({common_name})")
    print(f"    Valid Until      : {expiry_date.strftime('%Y-%m-%d')} ({days_left} days remaining)")

    # การแจ้งเตือนอายุใบรับรอง
    if days_left <= 0:
        print(f"    Status           : {Fore.RED}EXPIRED{Style.RESET_ALL}")
    elif days_left < 30:
        print(f"    Status           : {Fore.YELLOW}EXPIRING SOON (Less than 30 days){Style.RESET_ALL}")
    else:
        print(f"    Status           : {Fore.GREEN}VALID{Style.RESET_ALL}")

    # 2. ตรวจสอบโปรโตคอลเก่า (Legacy Protocols)
    print(f"\n{Fore.CYAN}[*] Testing Deprecated Protocol Support...{Style.RESET_ALL}")
    deprecated_protocols = [
        ("TLSv1.0", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1),
        ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1)
    ]

    for proto_name, proto_const in deprecated_protocols:
        if not proto_const:
            continue
        try:
            legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy_ctx.check_hostname = False
            legacy_ctx.verify_mode = ssl.CERT_NONE
            legacy_ctx.minimum_version = proto_const
            legacy_ctx.maximum_version = proto_const
            
            with socket.create_connection((hostname, port), timeout=4) as sock:
                with legacy_ctx.wrap_socket(sock, server_hostname=hostname):
                    print(f"  {Fore.RED}[!] Vulnerable:{Style.RESET_ALL} Server accepted {proto_name} (Deprecated)")
        except (ssl.SSLError, socket.error):
            print(f"  {Fore.GREEN}[+] Secure:{Style.RESET_ALL} Server rejected {proto_name}")

    print(f"\n{Fore.CYAN}=== Audit Completed ==={Style.RESET_ALL}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssl_checker.py <domain-or-ip>")
        sys.exit(1)

    host = parse_hostname(sys.argv[1])
    check_ssl_certificate(host)