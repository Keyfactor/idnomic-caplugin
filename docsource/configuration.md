## Overview

The Idnomic PKI Gateway plugin extends the capabilities of Idnomic PKI (formerly OpenTrust PKI) to Keyfactor Command via the Keyfactor AnyCA Gateway. This plugin leverages the Idnomic SOAP-based connectors to provide comprehensive certificate lifecycle management. The plugin represents a fully featured AnyCA Plugin with the following capabilities:

* **CA Sync**:
    * Download all certificates issued by the Idnomic CA
    * Support for incremental and full synchronization
    * Filter certificates by issuance date
* **Certificate Enrollment**:
    * Support certificate enrollment with new key pairs
    * Dynamic template (profile) discovery from the CA
    * Zone-based certificate issuance
    * Support for PKCS#10 CSR format
* **Certificate Revocation**:
    * Request revocation of previously issued certificates
    * Support for standard CRL revocation reasons

## Requirements

### Idnomic PKI System Prerequisites

Before configuring the AnyCA Gateway plugin, ensure the following prerequisites are met on your Idnomic PKI system:

1. **Idnomic PKI Installation**:
   - Idnomic PKI server must be installed and operational
   - RA (Registration Authority) connector must be enabled and accessible
   - SOAP interface must be configured and reachable

2. **Client Certificate Authentication**:
   - A client certificate must be issued for the AnyCA Gateway service to authenticate to Idnomic
   - The certificate must be trusted by the Idnomic PKI system
   - Certificate must be exported in PFX/PKCS#12 format with private key

3. **Network Connectivity**:
   - Gateway server must have network access to the Idnomic RA connector endpoint
   - Default endpoint format: `https://<server>:<port>/RA/connector.cgi`
   - TLS/SSL must be properly configured

### Obtaining Required Configuration Information

#### 1. RA Connector Endpoint Address

The RA Connector endpoint is the SOAP service URL for the Registration Authority connector.

**To find the endpoint address:**

1. Contact your Idnomic PKI administrator
2. The standard format is: `https://<hostname>:<port>/RA/connector.cgi`
3. Verify the endpoint is accessible from the Gateway server
4. Confirm SOAP services are enabled on this endpoint

**Example endpoint**: `https://idnomic-pki.example.com:8443/RA/connector.cgi`

#### 2. Client Certificate for Authentication

The Gateway authenticates to Idnomic using mutual TLS with a client certificate.

**Steps to obtain and prepare the client certificate:**

1. **Request a Client Certificate**:
   - Contact your Idnomic PKI administrator
   - Request a certificate suitable for SOAP client authentication
   - Ensure the certificate includes the "Client Authentication" Extended Key Usage

2. **Export the Certificate**:
   - Export the certificate with its private key in PFX (PKCS#12) format
   - Set a strong password for the PFX file
   - Example filename: `gateway-client-cert.pfx`

3. **Deploy the Certificate**:
   - Copy the PFX file to a secure location on the Gateway server
   - Recommended location: `C:\Program Files\Keyfactor\AnyGateway\Certificates\` (Windows)
   - Or: `/opt/keyfactor/anygateway/certificates/` (Linux)
   - Set appropriate file permissions to restrict access
   - Record the full path and password for Gateway configuration

#### 3. Certificate Profiles (Templates)

Certificate profiles define the types of certificates that can be issued. The plugin automatically discovers available profiles from the Idnomic system.

**To view available profiles:**

1. The profiles are retrieved automatically when the CA is configured
2. Profiles appear in Keyfactor Command as "Product IDs" after CA registration
3. Each profile represents a certificate template configured in Idnomic PKI

**Note**: Profile discovery uses the `list_profiles` SOAP operation. Ensure the client certificate has permissions to call this operation.

#### 4. Zones

Zones in Idnomic PKI represent organizational or security boundaries within the PKI hierarchy. Each certificate enrollment request must specify a zone.

**Common zone examples**:
- `Default`
- `Production`
- `Test`
- `DMZ`
- Custom zones as configured in your Idnomic PKI

**To identify available zones:**

1. Contact your Idnomic PKI administrator for the list of configured zones
2. Zones may be visible through the `certificate_search_properties` operation
3. Document the zone names exactly as they appear in the system (case-sensitive)

### Supported Revocation Reasons

The plugin supports the following standard CRL revocation reasons:

| Reason Code | Reason Name | Description |
|-------------|-------------|-------------|
| 0 | Unspecified | No specific reason provided |
| 1 | Key Compromise | Private key has been compromised |
| 2 | CA Compromise | Certificate Authority has been compromised |
| 3 | Affiliation Changed | Subject's affiliation has changed |
| 4 | Superseded | Certificate has been superseded by a new certificate |
| 5 | Cessation of Operation | Certificate is no longer needed |
| 6 | Certificate Hold | Temporary suspension (use with caution) |
| 9 | Privilege Withdrawn | Privileges have been withdrawn |
| 10 | AA Compromise | Attribute Authority has been compromised |

**Note**: Not all Idnomic PKI configurations support all revocation reasons. Consult your Idnomic administrator for supported reasons in your environment.

## Gateway Registration

TODO Gateway Registration is a required section

## Certificate Template Creation Step

TODO Certificate Template Creation Step is a required section

## Custom Enrollment Parameter Creation Step

TODO Custom Enrollment Parameter Creation Step is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info

## Mechanics

TODO Mechanics is an optional section. If this section doesn't seem necessary on initial glance, please delete it. Refer to the docs on [Confluence](https://keyfactor.atlassian.net/wiki/x/SAAyHg) for more info

