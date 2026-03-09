# make-selfsigned-cert.sh

## Purpose
make-selfsigned-cert.sh is a utility script that generates a self-signed TLS certificate and private key using OpenSSL. The script interactively prompts the user for certificate subject information such as country, state, city, organization, organizational unit, and common name. It is designed to quickly generate certificates for internal services, testing environments, or development systems.

## Features
The script performs the following actions:
Prompts the user for certificate subject information
Generates a 4096-bit RSA private key
Creates a self-signed certificate using OpenSSL
Stores the certificate and key in a dedicated directory
Applies secure permissions to the private key
Displays certificate details after creation

## Usage
Run the script as root:

sudo ./make-selfsigned-cert.sh

The script will prompt for certificate fields including:

Certificate name
Country
State
City
Organization
Organizational Unit
Common Name
Certificate validity period

If the user presses Enter without providing a value, the script will use default values which are the values in [] next to the name of the field.

## Output
Certificates are stored in the following directory:

/etc/ssl/localcerts/

Each certificate will generate two files:

<name>.key
<name>.crt

Example output files:

/etc/ssl/localcerts/kiosk-cert.key
/etc/ssl/localcerts/kiosk-cert.crt

## Security
The script applies secure file permissions:

Private key (.key): 600
Certificate (.crt): 644

This ensures that only the root user can read the private key while allowing the certificate to be publicly readable.

## Requirements
Linux system
OpenSSL installed
Root privileges

## Notes
These certificates are self-signed and are not trusted by public certificate authorities or browsers. They are intended for internal testing, development environments, or temporary service encryption.