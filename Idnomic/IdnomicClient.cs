/*
Copyright © 2025 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.AnyGateway.IdnomicCaProxy.IdnomicRaService;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.Idnomic.Client;

/// <summary>
/// Class <c>IdnomicClient</c> implements <see cref="IIdnomicClient"/> to provide a standard set of certificate-based operations on an Idnomic CA via SOAP service.
/// </summary>
public class IdnomicClient : IIdnomicClient
{
    private ILogger _logger;
    private OTPKIRAConnectorSOAPPortTypeClient _soapClient;
    private RequestManager _requestManager;

    bool _clientIsEnabled;

    string _endpointAddress;
    string _clientCertificateLocation;
    string _clientCertificatePassword;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdnomicClient"/> class.
    /// </summary>
    /// <param name="endpointAddress">The SOAP endpoint address for the Idnomic RA service.</param>
    /// <param name="clientCertificateLocation">The file path to the client certificate used for mutual TLS authentication.</param>
    /// <param name="clientCertificatePassword">The password for the client certificate.</param>
    public IdnomicClient(string endpointAddress, string clientCertificateLocation, string clientCertificatePassword)
    {
        _logger = LogHandler.GetClassLogger<IdnomicClient>();
        _logger.MethodEntry();
        _logger.LogDebug($"Creating Idnomic Client with Endpoint: {endpointAddress}");

        this._endpointAddress = endpointAddress;
        this._clientCertificateLocation = clientCertificateLocation;
        this._clientCertificatePassword = clientCertificatePassword;

        _logger.LogTrace($"Setting up SOAP client");
        InitializeSoapClient();

        _requestManager = new RequestManager();

        _logger.MethodExit();
    }

    private void InitializeSoapClient()
    {
        _logger.MethodEntry();

        // Force TLS 1.2+
        System.Net.ServicePointManager.SecurityProtocol =
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

        var binding = new BasicHttpsBinding
        {
            MaxReceivedMessageSize = int.MaxValue
        };

        binding.Security.Mode = BasicHttpsSecurityMode.Transport;
        binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;

        var endpoint = new EndpointAddress(_endpointAddress);
        _soapClient = new OTPKIRAConnectorSOAPPortTypeClient(binding, endpoint);

        // Load the client certificate WITH private key
        var cert = new X509Certificate2(
            _clientCertificateLocation,
            _clientCertificatePassword,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

        _soapClient.ClientCredentials.ClientCertificate.Certificate = cert;

        // 🔥 Ignore server-side certificate validation entirely (hostname + trust)
        _soapClient.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
            new System.ServiceModel.Security.X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };

        _logger.LogTrace("SOAP client created with client certificate and validation disabled");
        _logger.MethodExit();
    }


    public override string ToString()
    {
        return $"[endpointAddress={_endpointAddress}]";
    }

    /// <summary>
    /// Enables the <see cref="IdnomicClient"/> client. This must be called before any other operations are performed.
    /// </summary>
    /// <returns></returns>
    public Task Enable()
    {
        _logger.MethodEntry();
        if (!_clientIsEnabled)
        {
            _logger.LogDebug($"Enabling Idnomic client {this.ToString()}");
            _clientIsEnabled = true;
        }
        _logger.MethodExit();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Disables the <see cref="IdnomicClient"/> client. After this is called, no further operations can be performed until <see cref="Enable"/> is called.
    /// </summary>
    /// <returns></returns>
    public Task Disable()
    {
        _logger.MethodEntry();
        if (_clientIsEnabled)
        {
            _logger.LogDebug($"Disabling Idnomic client {this.ToString()}");
            _clientIsEnabled = false;
        }
        _logger.MethodExit();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Determines if the client is enabled.
    /// </summary>
    /// <returns>
    /// A <see cref="bool"/> indicating if the client is enabled.
    /// </returns>
    public bool IsEnabled()
    {
        _logger.MethodEntry();
        _logger.MethodExit();
        return _clientIsEnabled;
    }

    /// <summary>
    /// Attempts to connect to the Idnomic service to verify connectivity.
    /// </summary>
    /// <returns>
    /// Returns nothing if the connection is successful.
    /// </returns>
    /// <exception cref="Exception">Thrown if connection validation fails or if the <see cref="IdnomicClient"/> was not enabled via the <see cref="Enable"/> method.</exception>
    public async Task ValidateConnection()
    {
        _logger.MethodEntry();
        EnsureClientIsEnabled();

        try
        {
            _logger.LogTrace($"Testing connection to Idnomic service");
            // Perform a simple search to validate the connection
            var searchRequest = _requestManager.GetSearchRequest("DN=*", 1);
            await Task.Run(() => _soapClient.search_for_certificates(searchRequest));
            _logger.LogDebug($"Successfully validated connection to Idnomic service");
        }
        catch (Exception ex)
        {
            string error = $"Failed to validate connection to Idnomic service: {ex.Message}";
            _logger.LogError(error);
            throw new Exception(error, ex);
        }

        _logger.MethodExit();
    }

    /// <summary>
    /// Downloads all issued certificates from the Idnomic service and adds them to the provided <see cref="BlockingCollection{T}"/>.
    /// </summary>
    /// <param name="certificatesBuffer">
    /// A <see cref="BlockingCollection{T}"/> to which the downloaded certificates will be added.
    /// </param>
    /// <param name="cancelToken">
    /// A <see cref="CancellationToken"/> that can be used to cancel the operation.
    /// </param>
    /// <param name="issuedAfter">
    /// Optional parameter to filter certificates issued after a specific date/time. Currently not implemented for Idnomic.
    /// </param>
    /// <returns>
    /// The number of certificates downloaded.
    /// </returns>
    /// <exception cref="Exception">
    /// Thrown if the <see cref="BlockingCollection{T}"/> is null or if the operation fails.
    /// </exception>
    public async Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken, DateTime? issuedAfter = null)
    {
        _logger.MethodEntry();
        EnsureClientIsEnabled();

        if (certificatesBuffer == null)
        {
            string message = "Failed to download issued certificates - certificatesBuffer is null";
            _logger.LogError(message);
            throw new ArgumentNullException(nameof(certificatesBuffer), message);
        }

        _logger.LogDebug($"Downloading all issued certificates from Idnomic service {this.ToString()}");

        int numberOfCertificates = 0;

        try
        {
            var certItems = await Task.Run(() => GetCertificateItems(), cancelToken);
            _logger.LogTrace($"certItems Count: {certItems?.Count}");

            if (certItems != null)
            {
                foreach (var item in certItems)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        _logger.LogWarning("Certificate download operation was canceled.");
                        break;
                    }

                    var certProperties = item.Item1 as Item[];
                    var certificate = ParseCertificateFromProperties(certProperties);

                    if (certificate != null)
                    {
                        certificatesBuffer.Add(certificate, cancelToken);
                        numberOfCertificates++;
                        _logger.LogDebug($"Found Certificate with tracking ID {certificate.CARequestID}");
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Certificate download operation was canceled.");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Unexpected error while fetching certificates: {ex.Message}");
            throw;
        }
        finally
        {
            certificatesBuffer.CompleteAdding();
            _logger.LogDebug($"Fetched {numberOfCertificates} certificates from Idnomic service.");
        }

        _logger.MethodExit();
        return numberOfCertificates;
    }

    /// <summary>
    /// Downloads a certificate with the specified <paramref name="caRequestId"/> in PEM format and stores it in a <see cref="AnyCAPluginCertificate"/>.
    /// </summary>
    /// <param name="caRequestId">
    /// The CA Request ID (serial number) of the certificate to download.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as a <see cref="AnyCAPluginCertificate"/> containing the downloaded certificate.
    /// </returns>
    public async Task<AnyCAPluginCertificate> DownloadCertificate(string caRequestId)
    {
        _logger.MethodEntry();
        EnsureClientIsEnabled();

        _logger.LogDebug($"Downloading certificate with ID {caRequestId} {this.ToString()}");

        var certProperties = await Task.Run(() => GetCertificateByTrackingId(caRequestId));

        if (certProperties == null)
        {
            _logger.LogWarning($"Certificate with ID {caRequestId} not found");
            return new AnyCAPluginCertificate
            {
                CARequestID = caRequestId,
            };
        }

        var certificate = ParseCertificateFromProperties(certProperties);

        _logger.MethodExit();
        return certificate;
    }

    private AnyCAPluginCertificate ParseCertificateFromProperties(Item[] certProperties)
    {
        _logger.MethodEntry();

        if (certProperties == null)
        {
            return null;
        }

        var trackingId = certProperties.SingleOrDefault(cp => cp.key == "serial")?.Item1 as string;
        var pem = certProperties.SingleOrDefault(cp => cp.key == "certificate")?.Item1 as string;
        var notBefore = certProperties.SingleOrDefault(cp => cp.key == "notbefore")?.Item1 as string;
        var status = certProperties.SingleOrDefault(cp => cp.key == "status")?.Item1 as string;
        var productId = certProperties.SingleOrDefault(cp => cp.key == "profile")?.Item1 as string;

        if (string.IsNullOrEmpty(pem))
        {
            _logger.LogWarning("Certificate PEM is null or empty");
            return null;
        }

        var pemCert = pem;
        if (!pemCert.StartsWith("-----BEGIN CERTIFICATE-----"))
        {
            pemCert = "-----BEGIN CERTIFICATE-----\n" + pemCert;
        }
        if (!pemCert.EndsWith("-----END CERTIFICATE-----"))
        {
            pemCert += "\n-----END CERTIFICATE-----";
        }

        try
        {
            _ = new X509Certificate2(Encoding.ASCII.GetBytes(pemCert));

            _logger.MethodExit();
            return new AnyCAPluginCertificate
            {
                CARequestID = trackingId,
                Certificate = pemCert,
                Status = _requestManager.MapReturnStatus(status),
                ProductID = productId
            };
        }
        catch (Exception e)
        {
            _logger.LogError($"Error parsing certificate: {e.Message}");
            return null;
        }
    }

    /// <summary>
    /// Enrolls a certificate and returns the result.
    /// </summary>
    /// <param name="csr">
    /// The Certificate Signing Request in PEM format.
    /// </param>
    /// <param name="productId">
    /// The certificate profile/template ID to use for enrollment.
    /// </param>
    /// <param name="zone">
    /// The Idnomic zone identifier.
    /// </param>
    /// <param name="cancelToken">
    /// The <see cref="CancellationToken"/> to cancel the operation.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as an <see cref="EnrollmentResult"/> containing the result of the enrollment.
    /// </returns>
    public async Task<EnrollmentResult> Enroll(string csr, string productId, string zone, CancellationToken cancelToken)
    {
        try
        {
            _logger.MethodEntry();
            EnsureClientIsEnabled();

            _logger.LogTrace($"Enrolling certificate with profile {productId} in zone {zone}");
            var enrollmentRequest = _requestManager.GetEnrollRequest(csr, productId, zone);
            var response = await Task.Run(() => _soapClient.enroll(enrollmentRequest), cancelToken);

            if (response.Message.Item is Item[] items)
            {
                var pem = items.SingleOrDefault(cp => cp.key == "0")?.Item1 as string;
                if (!string.IsNullOrEmpty(pem))
                {
                    var currentCert = new X509Certificate2(Encoding.ASCII.GetBytes(pem));

                    _logger.LogTrace($"Certificate Subject: {currentCert.SubjectName}");

                    _logger.MethodExit();
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.GENERATED,
                        CARequestID = currentCert.SerialNumber,
                        Certificate = pem,
                        StatusMessage = $"Certificate successfully issued with serial number {currentCert.SerialNumber}"
                    };
                }
            }

            _logger.LogWarning("Enrollment response did not contain expected certificate data");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Enrollment failed - no certificate returned"
            };
        }
        catch (FaultException faultEx)
        {
            _logger.LogError($"SOAP Fault during enrollment: {faultEx.Code} {faultEx.Message}");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Enrollment failed: {faultEx.Code} {faultEx.Message}"
            };
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Certificate enrollment operation was canceled.");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Certificate enrollment was canceled."
            };
        }
        catch (Exception ex)
        {
            _logger.LogError($"Unexpected error during certificate enrollment: {ex.Message}");
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Unexpected error: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Revokes a certificate with the specified <paramref name="caRequestId"/> and <paramref name="revocationReason"/>.
    /// </summary>
    /// <param name="caRequestId">
    /// The CA Request ID (serial number) of the certificate to revoke.
    /// </param>
    /// <param name="revocationReason">
    /// The revocation reason code.
    /// </param>
    /// <returns></returns>
    public async Task RevokeCertificate(string caRequestId, uint revocationReason)
    {
        _logger.MethodEntry();
        EnsureClientIsEnabled();

        _logger.LogDebug($"Revoking certificate with ID {caRequestId} for reason {revocationReason} {this.ToString()}");

        var certProperties = await Task.Run(() => GetCertificateByTrackingId(caRequestId));

        if (certProperties == null)
        {
            throw new Exception($"Certificate with ID {caRequestId} not found");
        }

        var pem = certProperties.SingleOrDefault(cp => cp.key == "certificate")?.Item1 as string;
        var cert = new X509Certificate2(Encoding.ASCII.GetBytes(pem ?? string.Empty));
        var issuer = cert.Issuer;
        var reason = _requestManager.GetRevokeReasonText(revocationReason);
        var serialNumber = cert.SerialNumber;

        var revokeRequest = _requestManager.GetRevokeRequest(reason, issuer, serialNumber);
        var response = await Task.Run(() => _soapClient.revoke(revokeRequest));

        if (response.Message.Item != null && response.Message.Item as string == "0")
        {
            _logger.LogDebug($"Successfully revoked certificate with ID {caRequestId}");
        }
        else
        {
            throw new Exception($"Failed to revoke certificate with ID {caRequestId}");
        }

        _logger.MethodExit();
    }

    /// <summary>
    /// Retrieves the certificate profiles available in the Idnomic CA. 
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="string"/> containing the available certificate profile names.
    /// </returns>
    public List<string> GetTemplates()
    {
        _logger.MethodEntry();
        EnsureClientIsEnabled();

        // Idnomic doesn't have a direct API to list templates/profiles
        // This would need to be configured or discovered through other means
        _logger.LogDebug("GetTemplates called - returning empty list as Idnomic doesn't expose template enumeration");

        _logger.MethodExit();
        return new List<string>();
    }

    private Item[] GetCertificateByTrackingId(string serialNumber)
    {
        _logger.MethodEntry();

        try
        {
            var response = _soapClient.search_for_certificates(_requestManager.GetSearchRequest($"hexserial={serialNumber}", -1));

            if (response.Message.Item is Item[] items)
            {
                if (items.Length == 1)
                {
                    foreach (var i in items)
                    {
                        if (i.Item1 is Item[] certProperties)
                        {
                            _logger.MethodExit();
                            return certProperties;
                        }
                    }
                }
            }

            _logger.MethodExit();
            return null;
        }
        catch (Exception e)
        {
            _logger.LogError($"GetCertificateByTrackingId Error: {e.Message}");
            throw;
        }
    }

    private List<Item> GetCertificateItems()
    {
        _logger.MethodEntry();

        try
        {
            var response = _soapClient.search_for_certificates(_requestManager.GetSearchRequest("DN=*|+revocation=*|validAt=", -1));

            var itemList = new List<Item>();
            if (response.Message.Item is Item[] items)
            {
                itemList.AddRange(items.Where(i => i.Item1 is Item[]));
            }

            _logger.MethodExit();
            return itemList;
        }
        catch (Exception ex)
        {
            _logger.LogError($"GetCertificateItems error: {ex.Message}");
            throw;
        }
    }

    private void EnsureClientIsEnabled()
    {
        if (!_clientIsEnabled)
        {
            _logger.LogWarning("IdnomicClient is disabled - throwing");
            throw new Exception("IdnomicClient is disabled");
        }
    }
}