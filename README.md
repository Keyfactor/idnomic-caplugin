<h1 align="center" style="border-bottom: none">
    Idnomic PKI  Gateway AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-pilot-3D1973?style=flat-square" alt="Integration Status: pilot" />
<a href="https://github.com/Keyfactor/idnomic-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/idnomic-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/idnomic-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/idnomic-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


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

## Compatibility

The Idnomic PKI  Gateway AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The Idnomic PKI  Gateway AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

### Idnomic PKI System Prerequisites

Before configuring the AnyCA Gateway plugin, ensure the following prerequisites are met on your Idnomic PKI system:

1. **Idnomic PKI Installation**:
   - Idnomic PKI server must be installed and operational.  Only tested with 4.9.2 version of IDNOMIC.  Other version may or may not work.
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

**Note**: Not all Idnomic PKI configurations support all revocation reasons. Consult your Idnomic administrator for supported reasons in your environment.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Idnomic PKI  Gateway AnyCA Gateway REST plugin](https://github.com/Keyfactor/idnomic-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the Idnomic PKI  Gateway AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Idnomic PKI  Gateway plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        ### CA Connection Configuration

        When registering the Idnomic CA in the AnyCA Gateway, you'll need to provide the following configuration parameters:

        | Parameter | Description | Required | Example |
        |-----------|-------------|----------|---------|
        | **EndpointAddress** | Full URL to the Idnomic RA connector SOAP endpoint | Yes | `https://idnomic.example.com:8443/RA/connector.cgi` |
        | **ClientCertLocation** | Full file path to the client certificate PFX file on the Gateway server | Yes | `C:\Certificates\gateway-client.pfx` |
        | **ClientCertPassword** | Password for the client certificate PFX file | Yes | `SecureP@ssw0rd` |
        | **Enabled** | Whether the CA connection is enabled | No (default: true) | `true` or `false` |

        ### Template (Product) Configuration

        Each certificate template discovered from Idnomic requires configuration when used for enrollment:

        | Parameter | Description | Required | Example |
        |-----------|-------------|----------|---------|
        | **Zone** | The Idnomic PKI zone where certificates will be issued | Yes | `Production` |

        **Important Notes**:
        - Template names (Product IDs) are automatically discovered from Idnomic using the `list_profiles` operation
        - The Zone parameter must exactly match a zone configured in your Idnomic PKI system
        - Zone names are case-sensitive
        - Each template can be configured with a different zone if needed

        ### Gateway Registration Notes

        - Each defined Certificate Authority in the AnyCA Gateway REST can support one Idnomic CA endpoint
        - If you have multiple Idnomic PKI instances or need to issue from different zones with different permissions, you must define multiple Certificate Authorities in the AnyCA Gateway
        - Each CA configuration will manifest in Command as a separate CA entry
        - The plugin uses SOAP-based communication exclusively; ensure the RA connector endpoint is properly configured for SOAP access
        - Client certificate authentication is mandatory and cannot be disabled
        - The "Enabled" flag allows you to temporarily disable a CA connection without removing the configuration

        ### Security Considerations

        1. **Certificate Storage**: Store client certificates in a secure location with restricted file system permissions
        2. **Password Management**: Use strong passwords for client certificate PFX files and consider using a secrets management system
        3. **Network Security**: Ensure TLS/SSL is properly configured for the RA connector endpoint
        4. **Least Privilege**: Request client certificates with minimal required permissions in the Idnomic PKI system
        5. **Audit Logging**: Enable comprehensive logging in both the Gateway and Idnomic PKI for security monitoring

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **EndpointAddress** - The SOAP endpoint address for the Idnomic RA service. For example, 'https://idnomic-server.com/ra-service'. 
        * **ClientCertLocation** - The file path to the client certificate used for mutual TLS authentication with the Idnomic service. 
        * **ClientCertPassword** - The password for the client certificate. 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.


## Troubleshooting

### Connection Issues
- Verify the RA connector endpoint URL is correct and accessible
- Check that the client certificate is valid and not expired
- Confirm the client certificate is trusted by the Idnomic PKI system
- Review Gateway logs for SOAP communication errors

### Profile Discovery Issues
- Ensure the client certificate has permissions to call `list_profiles`
- Verify the RA connector is properly configured in Idnomic
- Check that profiles are published and available in the Idnomic system

### Enrollment Failures
- Verify the Zone parameter exactly matches a configured zone in Idnomic
- Confirm the selected profile supports the requested certificate attributes
- Check that the client certificate has enrollment permissions for the specified zone
- Review Idnomic PKI logs for detailed error messages

### Synchronization Issues
- Confirm the client certificate has permissions to call `search_for_certificates`
- Verify network connectivity and timeout settings
- For large certificate databases, consider adjusting synchronization schedules

## Test Cases

### Test Case 1: CA Connection Validation

**Objective**: Verify that the Gateway can successfully connect to the Idnomic RA connector using client certificate authentication.

**Prerequisites**:
- Idnomic PKI system is operational
- Valid client certificate (PFX) is available
- RA connector endpoint is accessible

**Test Steps**:
1. Configure the CA in AnyCA Gateway with valid connection parameters
2. Click "Test Connection" or trigger the Ping operation
3. Observe the connection result

**Expected Results**:
- Connection succeeds without errors
- Gateway logs show successful SOAP authentication
- No certificate validation errors occur

**Verification**:
- Review Gateway logs for successful connection message
- Check Idnomic PKI logs for incoming authenticated connection
- Verify no SSL/TLS errors in either system

---

### Test Case 2: Profile Discovery

**Objective**: Verify that the Gateway can retrieve the list of available certificate profiles from Idnomic PKI.

**Prerequisites**:
- CA connection is successfully configured
- At least one certificate profile is configured in Idnomic PKI
- Client certificate has permissions to call `list_profiles`

**Test Steps**:
1. Save the CA configuration in AnyCA Gateway
2. Navigate to the template/product configuration section
3. Observe the list of available Product IDs

**Expected Results**:
- List of profiles is populated automatically
- Profile names match those configured in Idnomic PKI
- No empty or null profile names appear

**Verification**:
- Compare the list of profiles in Gateway with Idnomic PKI configuration
- Verify profile names are correctly displayed
- Check Gateway logs for successful `list_profiles` SOAP call

---

### Test Case 3: Certificate Enrollment - Valid Request

**Objective**: Verify successful certificate enrollment through the plugin.

**Prerequisites**:
- CA and template are properly configured
- Valid Zone parameter is configured for the template
- Test CSR is available

**Test Steps**:
1. Submit an enrollment request via Keyfactor Command
2. Specify the Idnomic CA and a valid template
3. Provide a valid PKCS#10 CSR
4. Wait for enrollment to complete

**Expected Results**:
- Enrollment completes successfully
- Certificate is issued by Idnomic PKI
- Certificate is returned to Keyfactor Command
- Certificate appears in Command inventory

**Verification**:
- Verify certificate details match the CSR
- Confirm certificate is present in Idnomic PKI database
- Check that certificate chain is properly constructed
- Validate certificate can be used for its intended purpose

---

### Test Case 4: Certificate Enrollment - Invalid Zone

**Objective**: Verify proper error handling when an invalid zone is specified.

**Prerequisites**:
- CA and template are configured
- Zone parameter is set to a non-existent zone name

**Test Steps**:
1. Submit an enrollment request with invalid Zone parameter
2. Observe the enrollment result

**Expected Results**:
- Enrollment fails with clear error message
- Error message indicates invalid zone
- No certificate is issued
- System remains stable

**Verification**:
- Check error message clarity and accuracy
- Verify Gateway logs contain detailed error information
- Confirm no partial enrollment occurred in Idnomic PKI

---

### Test Case 5: Certificate Synchronization - Full Sync

**Objective**: Verify full certificate synchronization from Idnomic PKI to Keyfactor Command.

**Prerequisites**:
- CA is properly configured
- Multiple certificates exist in Idnomic PKI
- Synchronization is configured in Command

**Test Steps**:
1. Trigger a full synchronization job
2. Wait for synchronization to complete
3. Verify synchronized certificate count

**Expected Results**:
- All certificates from Idnomic PKI are synchronized
- Certificate details are accurate (subject, serial number, dates, etc.)
- No duplicate certificates appear
- Synchronization completes without errors

**Verification**:
- Compare certificate count in Command vs. Idnomic PKI
- Spot-check several certificates for data accuracy
- Review synchronization logs for any warnings or errors
- Verify certificate chains are properly synchronized

---

### Test Case 6: Certificate Synchronization - Incremental Sync

**Objective**: Verify incremental synchronization only retrieves new certificates since last sync.

**Prerequisites**:
- Initial full synchronization has been completed
- Timestamp of last sync is recorded
- New certificates have been issued since last sync

**Test Steps**:
1. Note the timestamp of the last successful sync
2. Issue one or more new certificates in Idnomic PKI
3. Trigger an incremental synchronization
4. Observe synchronized certificates

**Expected Results**:
- Only certificates issued after last sync are retrieved
- Sync completes faster than full sync
- All new certificates are properly synchronized
- Previously synchronized certificates are not duplicated

**Verification**:
- Verify only recent certificates were processed
- Check sync duration is appropriate for certificate count
- Review Gateway logs to confirm incremental sync parameters
- Validate certificate data integrity

---

### Test Case 7: Certificate Revocation - Key Compromise

**Objective**: Verify certificate revocation with reason code 1 (Key Compromise).

**Prerequisites**:
- A valid certificate issued through the Gateway exists
- Certificate is not already revoked

**Test Steps**:
1. Identify a test certificate to revoke
2. Submit revocation request with reason "Key Compromise" (code 1)
3. Wait for revocation to complete

**Expected Results**:
- Revocation succeeds
- Certificate status changes to "Revoked" in Command
- Certificate appears on CRL in Idnomic PKI
- Revocation reason is correctly recorded

**Verification**:
- Check certificate status in Keyfactor Command
- Verify certificate appears on Idnomic CRL with correct reason code
- Confirm revocation timestamp is accurate
- Validate certificate can no longer be used for authentication

---

### Test Case 8: Profile Properties Validation

**Objective**: Verify that profile-specific properties are correctly enforced during enrollment.

**Prerequisites**:
- Profiles with different configurations exist (key sizes, validity periods, etc.)
- Zone parameter is correctly configured

**Test Steps**:
1. Attempt enrollment with CSR matching profile requirements
2. Attempt enrollment with CSR not matching profile requirements (e.g., wrong key size)
3. Observe results

**Expected Results**:
- Valid enrollments succeed
- Invalid enrollments fail with descriptive error messages
- Profile constraints are properly enforced by Idnomic PKI

**Verification**:
- Review error messages for clarity
- Verify Idnomic PKI rejects non-compliant requests
- Check that valid certificates meet profile specifications
- Confirm Gateway properly communicates validation errors

---


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).