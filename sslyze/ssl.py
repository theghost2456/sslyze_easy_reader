import re

def parse_sslyze_text(sslyze_text):
    results = []

    # Regex patterns for parsing
    hostname_pattern = re.compile(r'SCAN RESULTS FOR (\S+):(\d+) - (\S+)')
    tls12_accepted_cipher_pattern = re.compile(r'TLS 1.2 Cipher Suites:\s*\n((?:\s+TLS[^\n]+\n)+)')
    tls13_accepted_cipher_pattern = re.compile(r'TLS 1.3 Cipher Suites:\s*\n((?:\s+TLS[^\n]+\n)+)')
    cipher_pattern = re.compile(r'\s+(TLS[^\s]+)')
    rejected_ciphers_pattern = re.compile(r'ciphers: Cipher suites \{([^\}]+)\} are supported, but should be rejected.')
    cert_lifespan_pattern = re.compile(r'Certificate life span is (\d+) days, should be less than (\d+).')

    # Reading SSLyze text output
    with open(sslyze_text, 'r') as file:
        data = file.read()
    
    # Extract hostname information
    hostname_match = hostname_pattern.search(data)
    if hostname_match:
        hostname = hostname_match.group(1)
        port = hostname_match.group(2)
        ip_address = hostname_match.group(3)
        results.append(f"Hostname: {hostname}, Port: {port}, IP Address: {ip_address}")

    # Extract certificate lifespan
    cert_lifespan_match = cert_lifespan_pattern.search(data)
    if cert_lifespan_match:
        cert_lifespan = cert_lifespan_match.group(1)
        max_cert_lifespan = cert_lifespan_match.group(2)
        results.append(f"Certificate Lifespan: {cert_lifespan} days")
        results.append(f"Maximum Certificate Lifespan: {max_cert_lifespan} days")

    # Extract accepted ciphers for TLS 1.2
    tls12_match = tls12_accepted_cipher_pattern.search(data)
    if tls12_match:
        tls12_ciphers = tls12_match.group(1).strip().split('\n')
        for cipher in tls12_ciphers:
            cipher_name = cipher_pattern.search(cipher).group(1)
            results.append(f"Accepted TLS 1.2 Cipher: {cipher_name}")

    # Extract accepted ciphers for TLS 1.3
    tls13_match = tls13_accepted_cipher_pattern.search(data)
    if tls13_match:
        tls13_ciphers = tls13_match.group(1).strip().split('\n')
        for cipher in tls13_ciphers:
            cipher_name = cipher_pattern.search(cipher).group(1)
            results.append(f"Accepted TLS 1.3 Cipher: {cipher_name}")

    # Extract ciphers that are accepted but should be rejected
    rejected_ciphers_match = rejected_ciphers_pattern.search(data)
    if rejected_ciphers_match:
        rejected_ciphers = rejected_ciphers_match.group(1).replace("'", "").strip().split(", ")
        for cipher in rejected_ciphers:
            results.append(cipher)

    return results

def main():
    sslyze_text = 'sslyze_results.txt'  # Update to the correct path of your sslyze results file
    output_txt = input("Enter the output file name (default: parsed_results.txt): ")
    
    # If the user doesn't provide an extension, add ".txt"
    if not output_txt:
        output_txt = 'parsed_results.txt'
    elif not output_txt.endswith('.txt'):
        output_txt += '.txt'

    results = parse_sslyze_text(sslyze_text)
    
    with open(output_txt, 'w') as file:
        for result in results:
            file.write(result + '\n')

if __name__ == "__main__":
    main()

