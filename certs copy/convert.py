import os

def convert_cert_chain():
    # Read the certificate chain
    with open('ca_chain.crt', 'r') as f:
        cert_chain = f.read()

    # Replace actual newlines with \n
    one_line = cert_chain.replace('\n', '\\n')

    # Write to a new file
    with open('ca_chain_oneline.txt', 'w') as f:
        f.write(one_line)

    print("Certificate chain converted to one line")

if __name__ == "__main__":
    convert_cert_chain()
