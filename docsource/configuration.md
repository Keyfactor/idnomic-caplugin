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
