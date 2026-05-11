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
    private readonly ILogger _logger;
    private OTPKIRAConnectorSOAPPortTypeClient _soapClient;
    private RequestManager _requestManager;

    bool _clientIsEnabled;

    string _endpointAddress;
    string _clientCertificateLocation;
    string _clientCertificatePassword;
    string _issuerDnFilter;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdnomicClient"/> class.
    /// </summary>
    /// <param name="endpointAddress">The SOAP endpoint address for the Idnomic RA service.</param>
    /// <param name="clientCertificateLocation">The file path to the client certificate used for mutual TLS authentication.</param>
    /// <param name="clientCertificatePassword">The password for the client certificate.</param>
    /// <param name="issuerDnFilter">Optional filter to restrict synchronized certificates by Issuer DN (case-insensitive substring match).</param>
    public IdnomicClient(string endpointAddress, string clientCertificateLocation, string clientCertificatePassword, string issuerDnFilter = null)
    {
        _logger = LogHandler.GetClassLogger<IdnomicClient>();
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("IdnomicClient constructor called. endpointAddress='{Endpoint}', clientCertificateLocation='{CertLocation}', issuerDnFilter='{Filter}'",
            endpointAddress ?? "(null)",
            clientCertificateLocation ?? "(null)",
            issuerDnFilter ?? "(null)");

        if (string.IsNullOrEmpty(endpointAddress))
            throw new ArgumentNullException(nameof(endpointAddress), "endpointAddress cannot be null or empty.");
        if (string.IsNullOrEmpty(clientCertificateLocation))
            throw new ArgumentNullException(nameof(clientCertificateLocation), "clientCertificateLocation cannot be null or empty.");
        if (string.IsNullOrEmpty(clientCertificatePassword))
            throw new ArgumentNullException(nameof(clientCertificatePassword), "clientCertificatePassword cannot be null or empty.");

        this._endpointAddress = endpointAddress;
        this._clientCertificateLocation = clientCertificateLocation;
        this._clientCertificatePassword = clientCertificatePassword;
        this._issuerDnFilter = issuerDnFilter;

        if (!string.IsNullOrEmpty(_issuerDnFilter))
        {
            _logger.LogDebug("Issuer DN filter configured: '{IssuerDnFilter}'", _issuerDnFilter);
        }
        else
        {
            _logger.LogTrace("No issuer DN filter configured - all certificates will be included");
        }

        _logger.LogTrace("Setting up SOAP client");
        InitializeSoapClient();

        _requestManager = new RequestManager();

        _logger.LogDebug("IdnomicClient created successfully for endpoint='{Endpoint}'", _endpointAddress);
        _logger.MethodExit(LogLevel.Debug);
    }

    private void InitializeSoapClient()
    {
        _logger.MethodEntry(LogLevel.Debug);

        // Force TLS 1.2+ (ServicePointManager is obsolete in .NET 10+, where TLS 1.2+ is the default)
#if !NET10_0_OR_GREATER
        System.Net.ServicePointManager.SecurityProtocol =
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
        _logger.LogTrace("SecurityProtocol set to TLS 1.2 | TLS 1.3");
#else
        _logger.LogTrace("TLS 1.2+ is enforced by default on .NET 10+");
#endif

        var binding = new BasicHttpsBinding
        {
            MaxReceivedMessageSize = int.MaxValue
        };

        binding.Security.Mode = BasicHttpsSecurityMode.Transport;
        binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
        _logger.LogTrace("HTTPS binding configured with Transport security and Certificate client credential type");

        var endpoint = new EndpointAddress(_endpointAddress);
        _soapClient = new OTPKIRAConnectorSOAPPortTypeClient(binding, endpoint);
        _logger.LogTrace("SOAP client instantiated for endpoint='{Endpoint}'", _endpointAddress);

        try
        {
            var cert = LoadCertificateFromFile(
                _clientCertificateLocation,
                _clientCertificatePassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

            _soapClient.ClientCredentials.ClientCertificate.Certificate = cert;
            _logger.LogTrace("Client certificate loaded. Subject='{Subject}', Thumbprint='{Thumbprint}', NotAfter={NotAfter}",
                cert.Subject, cert.Thumbprint, cert.NotAfter.ToString("o"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load client certificate from '{CertLocation}': {Message}",
                _clientCertificateLocation, ex.Message);
            throw new InvalidOperationException(
                $"Failed to load client certificate from '{_clientCertificateLocation}': {ex.Message}", ex);
        }

        // Ignore server-side certificate validation entirely (hostname + trust)
        _soapClient.ClientCredentials.ServiceCertificate.SslCertificateAuthentication =
            new System.ServiceModel.Security.X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
                RevocationMode = X509RevocationMode.NoCheck
            };

        _logger.LogTrace("SOAP client created with client certificate and server validation disabled");
        _logger.MethodExit(LogLevel.Debug);
    }

    public override string ToString()
    {
        return $"[endpointAddress={_endpointAddress}, issuerDnFilter={_issuerDnFilter ?? "(none)"}]";
    }

    /// <summary>
    /// Enables the <see cref="IdnomicClient"/> client.
    /// </summary>
    public Task Enable()
    {
        _logger.MethodEntry(LogLevel.Debug);
        if (!_clientIsEnabled)
        {
            _logger.LogDebug("Enabling Idnomic client {Client}", this.ToString());
            _clientIsEnabled = true;
        }
        else
        {
            _logger.LogTrace("Idnomic client already enabled");
        }
        _logger.MethodExit(LogLevel.Debug);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Disables the <see cref="IdnomicClient"/> client.
    /// </summary>
    public Task Disable()
    {
        _logger.MethodEntry(LogLevel.Debug);
        if (_clientIsEnabled)
        {
            _logger.LogDebug("Disabling Idnomic client {Client}", this.ToString());
            _clientIsEnabled = false;
        }
        else
        {
            _logger.LogTrace("Idnomic client already disabled");
        }
        _logger.MethodExit(LogLevel.Debug);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Determines if the client is enabled.
    /// </summary>
    public bool IsEnabled()
    {
        _logger.LogTrace("IsEnabled called. Returning {Enabled}", _clientIsEnabled);
        return _clientIsEnabled;
    }

    /// <summary>
    /// Attempts to connect to the Idnomic service to verify connectivity.
    /// </summary>
    public async Task ValidateConnection()
    {
        using var flow = new FlowLogger(_logger, "ValidateConnection");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        try
        {
            await flow.StepAsync("SearchForCertificates", async () =>
            {
                _logger.LogTrace("Testing connection to Idnomic service with DN=* search");
                var searchRequest = _requestManager.GetSearchRequest("DN=*", 1);
                var response = await Task.Run(() => _soapClient.search_for_certificates(searchRequest));
                _logger.LogTrace("ValidateConnection: SOAP response received. Item is {ItemState}",
                    response?.Message?.Item == null ? "NULL" : "present");
            });

            _logger.LogDebug("Successfully validated connection to Idnomic service");
        }
        catch (FaultException faultEx)
        {
            flow.Fail("SOAPFault", $"{faultEx.Code} {faultEx.Message}");
            _logger.LogError(faultEx, "SOAP Fault during connection validation: Code={Code}, Message={Message}",
                faultEx.Code, faultEx.Message);
            throw new Exception($"Failed to validate connection to Idnomic service (SOAP Fault): {faultEx.Message}", faultEx);
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            _logger.LogError(ex, "Failed to validate connection to Idnomic service: {Message}", ex.Message);
            throw new Exception($"Failed to validate connection to Idnomic service: {ex.Message}", ex);
        }

        _logger.MethodExit(LogLevel.Debug);
    }

    /// <summary>
    /// Downloads all issued certificates from the Idnomic service and adds them to the provided <see cref="BlockingCollection{T}"/>.
    /// </summary>
    public async Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken, DateTime? issuedAfter = null)
    {
        using var flow = new FlowLogger(_logger, "DownloadAllIssuedCertificates");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        _logger.LogTrace("DownloadAllIssuedCertificates called. certificatesBuffer is {BufferState}, issuedAfter={IssuedAfter}",
            certificatesBuffer == null ? "NULL" : "present",
            issuedAfter?.ToString("o") ?? "(null)");

        flow.Step("ValidateInputs", () =>
        {
            if (certificatesBuffer == null)
                throw new ArgumentNullException(nameof(certificatesBuffer), "certificatesBuffer cannot be null.");
        });

        _logger.LogDebug("Downloading all issued certificates from Idnomic service {Client}", this.ToString());

        int numberOfCertificates = 0;
        int skippedCount = 0;
        int filteredCount = 0;
        int errorCount = 0;

        try
        {
            List<Item> certItems = null;

            await flow.StepAsync("FetchCertificateItems", async () =>
            {
                certItems = await Task.Run(() => GetCertificateItems(), cancelToken);
            });

            _logger.LogDebug("Retrieved {Count} raw certificate items from Idnomic service",
                certItems?.Count ?? 0);

            if (certItems != null)
            {
                foreach (var item in certItems)
                {
                    cancelToken.ThrowIfCancellationRequested();

                    if (item == null)
                    {
                        skippedCount++;
                        continue;
                    }

                    var certProperties = item.Item1 as Item[];
                    AnyCAPluginCertificate certificate = null;

                    try
                    {
                        certificate = ParseCertificateFromProperties(certProperties);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "DownloadAllIssuedCertificates: ParseCertificateFromProperties failed: {Message}", ex.Message);
                        errorCount++;
                        continue;
                    }

                    if (certificate == null)
                    {
                        skippedCount++;
                        continue;
                    }

                    if (!PassesIssuerFilter(certificate.Certificate))
                    {
                        filteredCount++;
                        continue;
                    }

                    try
                    {
                        certificatesBuffer.Add(certificate, cancelToken);
                        numberOfCertificates++;
                        _logger.LogTrace("Added certificate with tracking ID '{TrackingId}' to buffer", certificate.CARequestID ?? "(null)");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "DownloadAllIssuedCertificates: Failed to add certificate '{TrackingId}' to buffer: {Message}",
                            certificate.CARequestID ?? "(null)", ex.Message);
                        errorCount++;
                    }
                }
            }

            flow.Step("ProcessingComplete",
                $"Added={numberOfCertificates}, Filtered={filteredCount}, Skipped={skippedCount}, Errors={errorCount}");
        }
        catch (OperationCanceledException)
        {
            flow.Fail("Cancelled", "operation was cancelled");
            _logger.LogWarning("Certificate download operation was cancelled. Processed={Processed} so far", numberOfCertificates);
            throw;
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            _logger.LogError(ex, "Unexpected error while fetching certificates: {Message}", ex.Message);
            throw;
        }
        finally
        {
            if (!certificatesBuffer.IsAddingCompleted)
            {
                certificatesBuffer.CompleteAdding();
            }
            _logger.LogDebug("DownloadAllIssuedCertificates complete. Added={Added}, Filtered={Filtered}, Skipped={Skipped}, Errors={Errors}",
                numberOfCertificates, filteredCount, skippedCount, errorCount);
        }

        _logger.MethodExit(LogLevel.Debug);
        return numberOfCertificates;
    }

    /// <summary>
    /// Downloads a certificate with the specified <paramref name="caRequestId"/> in PEM format and stores it in a <see cref="AnyCAPluginCertificate"/>.
    /// </summary>
    public async Task<AnyCAPluginCertificate> DownloadCertificate(string caRequestId)
    {
        using var flow = new FlowLogger(_logger, $"DownloadCertificate({caRequestId ?? "(null)"})");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        _logger.LogTrace("DownloadCertificate called. caRequestId='{CaRequestId}'", caRequestId ?? "(null)");

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestId))
                throw new ArgumentNullException(nameof(caRequestId), "caRequestId cannot be null or empty.");
        });

        _logger.LogDebug("Downloading certificate with ID '{CaRequestId}' {Client}", caRequestId, this.ToString());

        Item[] certProperties = null;

        try
        {
            await flow.StepAsync("SearchByTrackingId", async () =>
            {
                certProperties = await Task.Run(() => GetCertificateByTrackingId(caRequestId));
            });
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            _logger.LogError(ex, "DownloadCertificate: Error searching for certificate '{CaRequestId}': {Message}",
                caRequestId, ex.Message);
            throw;
        }

        if (certProperties == null)
        {
            flow.Fail("CertificateNotFound", $"No certificate found for ID '{caRequestId}'");
            _logger.LogWarning("Certificate with ID '{CaRequestId}' not found", caRequestId);
            _logger.MethodExit(LogLevel.Debug);
            return new AnyCAPluginCertificate
            {
                CARequestID = caRequestId,
            };
        }

        AnyCAPluginCertificate certificate = null;
        flow.Step("ParseCertificate", () =>
        {
            certificate = ParseCertificateFromProperties(certProperties);
        });

        if (certificate == null)
        {
            flow.Fail("ParseFailed", "ParseCertificateFromProperties returned null");
            _logger.LogWarning("DownloadCertificate: Failed to parse certificate properties for ID '{CaRequestId}'", caRequestId);
            _logger.MethodExit(LogLevel.Debug);
            return new AnyCAPluginCertificate
            {
                CARequestID = caRequestId,
            };
        }

        if (!PassesIssuerFilter(certificate.Certificate))
        {
            flow.Skip("IssuerFilterApplied", $"Certificate filtered out by IssuerDnFilter '{_issuerDnFilter}'");
            _logger.LogDebug("Certificate with ID '{CaRequestId}' filtered out by IssuerDnFilter", caRequestId);
            _logger.MethodExit(LogLevel.Debug);
            return new AnyCAPluginCertificate
            {
                CARequestID = caRequestId,
            };
        }

        _logger.LogTrace("DownloadCertificate: Returning certificate. CARequestID='{CaRequestId}', Status={Status}, ProductID='{ProductId}'",
            certificate.CARequestID ?? "(null)",
            certificate.Status,
            certificate.ProductID ?? "(null)");

        _logger.MethodExit(LogLevel.Debug);
        return certificate;
    }

    private AnyCAPluginCertificate ParseCertificateFromProperties(Item[] certProperties)
    {
        _logger.MethodEntry(LogLevel.Debug);

        if (certProperties == null)
        {
            _logger.LogTrace("ParseCertificateFromProperties: certProperties is null, returning null");
            return null;
        }

        _logger.LogTrace("ParseCertificateFromProperties: processing {Count} properties", certProperties.Length);

        var trackingId = certProperties.SingleOrDefault(cp => cp.key == "serial")?.Item1 as string;
        var pem = certProperties.SingleOrDefault(cp => cp.key == "certificate")?.Item1 as string;
        var notBefore = certProperties.SingleOrDefault(cp => cp.key == "notbefore")?.Item1 as string;
        var status = certProperties.SingleOrDefault(cp => cp.key == "status")?.Item1 as string;
        var productId = certProperties.SingleOrDefault(cp => cp.key == "profile")?.Item1 as string;

        _logger.LogTrace("ParseCertificateFromProperties: trackingId='{TrackingId}', pem is {PemState}, status='{Status}', productId='{ProductId}'",
            trackingId ?? "(null)",
            string.IsNullOrEmpty(pem) ? "NULL/empty" : $"present ({pem.Length} chars)",
            status ?? "(null)",
            productId ?? "(null)");

        if (string.IsNullOrEmpty(pem))
        {
            _logger.LogWarning("ParseCertificateFromProperties: Certificate PEM is null or empty for trackingId='{TrackingId}'",
                trackingId ?? "(null)");
            return null;
        }

        var pemCert = pem;
        if (!pemCert.StartsWith("-----BEGIN CERTIFICATE-----"))
        {
            pemCert = "-----BEGIN CERTIFICATE-----\n" + pemCert;
            _logger.LogTrace("ParseCertificateFromProperties: Prepended BEGIN marker for trackingId='{TrackingId}'", trackingId ?? "(null)");
        }
        if (!pemCert.EndsWith("-----END CERTIFICATE-----"))
        {
            pemCert += "\n-----END CERTIFICATE-----";
            _logger.LogTrace("ParseCertificateFromProperties: Appended END marker for trackingId='{TrackingId}'", trackingId ?? "(null)");
        }

        try
        {
            var x509 = LoadCertificateFromPem(Encoding.ASCII.GetBytes(pemCert));
            _logger.LogTrace("ParseCertificateFromProperties: X509 parsed. Subject='{Subject}', Issuer='{Issuer}', Serial='{Serial}'",
                x509.Subject, x509.Issuer, x509.SerialNumber);

            var mappedStatus = _requestManager.MapReturnStatus(status);

            _logger.MethodExit(LogLevel.Debug);
            return new AnyCAPluginCertificate
            {
                CARequestID = trackingId,
                Certificate = pemCert,
                Status = mappedStatus,
                ProductID = productId
            };
        }
        catch (Exception e)
        {
            _logger.LogError(e, "ParseCertificateFromProperties: Error parsing certificate for trackingId='{TrackingId}': {Message}",
                trackingId ?? "(null)", e.Message);
            return null;
        }
    }

    /// <summary>
    /// Enrolls a certificate and returns the result.
    /// </summary>
    public async Task<EnrollmentResult> Enroll(string csr, string productId, string zone, CancellationToken cancelToken)
    {
        using var flow = new FlowLogger(_logger, $"Enroll(productId={productId ?? "(null)"}, zone={zone ?? "(null)"})");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        _logger.LogTrace("Enroll called. csr is {CsrState}, productId='{ProductId}', zone='{Zone}'",
            string.IsNullOrEmpty(csr) ? "NULL/empty" : $"present ({csr.Length} chars)",
            productId ?? "(null)",
            zone ?? "(null)");

        flow.Step("ValidateInputs", () =>
        {
            if (string.IsNullOrEmpty(csr))
                throw new ArgumentException("CSR cannot be null or empty.", nameof(csr));
            if (string.IsNullOrEmpty(productId))
                throw new ArgumentException("productId cannot be null or empty.", nameof(productId));
            if (string.IsNullOrEmpty(zone))
                throw new ArgumentException("zone cannot be null or empty.", nameof(zone));
        });

        try
        {
            OTMessageType response = null;

            await flow.StepAsync("SubmitEnrollRequest", async () =>
            {
                _logger.LogTrace("Building enrollment request for profile '{ProductId}' in zone '{Zone}'", productId, zone);
                var enrollmentRequest = _requestManager.GetEnrollRequest(csr, productId, zone);
                response = await Task.Run(() => _soapClient.enroll(enrollmentRequest), cancelToken);
            });

            _logger.LogTrace("Enroll: SOAP response received. Item is {ItemType}",
                response?.Message?.Item?.GetType()?.Name ?? "NULL");

            if (response?.Message?.Item is Item[] items)
            {
                var pem = items.SingleOrDefault(cp => cp.key == "0")?.Item1 as string;
                _logger.LogTrace("Enroll: PEM from response is {PemState}",
                    string.IsNullOrEmpty(pem) ? "NULL/empty" : $"present ({pem.Length} chars)");

                if (!string.IsNullOrEmpty(pem))
                {
                    X509Certificate2 currentCert;
                    try
                    {
                        currentCert = LoadCertificateFromPem(Encoding.ASCII.GetBytes(pem));
                    }
                    catch (Exception ex)
                    {
                        flow.Fail("ParseCertificate", ex.Message);
                        _logger.LogError(ex, "Enroll: Failed to parse returned certificate PEM: {Message}", ex.Message);
                        _logger.MethodExit(LogLevel.Debug);
                        return new EnrollmentResult
                        {
                            Status = (int)EndEntityStatus.FAILED,
                            StatusMessage = $"Enrollment succeeded but certificate could not be parsed: {ex.Message}"
                        };
                    }

                    _logger.LogDebug("Certificate enrolled successfully. Subject='{Subject}', SerialNumber='{Serial}'",
                        currentCert.Subject, currentCert.SerialNumber);

                    _logger.MethodExit(LogLevel.Debug);
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.GENERATED,
                        CARequestID = currentCert.SerialNumber,
                        Certificate = pem,
                        StatusMessage = $"Certificate successfully issued with serial number {currentCert.SerialNumber}"
                    };
                }
            }

            flow.Fail("NoCertificateInResponse", "Enrollment response did not contain expected certificate data");
            _logger.LogWarning("Enrollment response did not contain expected certificate data");
            _logger.MethodExit(LogLevel.Debug);
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Enrollment failed - no certificate returned"
            };
        }
        catch (FaultException faultEx)
        {
            flow.Fail("SOAPFault", $"{faultEx.Code} {faultEx.Message}");
            _logger.LogError(faultEx, "SOAP Fault during enrollment: Code={Code}, Message={Message}", faultEx.Code, faultEx.Message);
            _logger.MethodExit(LogLevel.Debug);
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Enrollment failed (SOAP Fault): {faultEx.Code} {faultEx.Message}"
            };
        }
        catch (OperationCanceledException)
        {
            flow.Fail("Cancelled", "enrollment was cancelled");
            _logger.LogWarning("Certificate enrollment operation was cancelled");
            _logger.MethodExit(LogLevel.Debug);
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = "Certificate enrollment was cancelled."
            };
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            _logger.LogError(ex, "Unexpected error during certificate enrollment: {Message}", ex.Message);
            _logger.MethodExit(LogLevel.Debug);
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
    public async Task RevokeCertificate(string caRequestId, uint revocationReason)
    {
        using var flow = new FlowLogger(_logger, $"RevokeCertificate({caRequestId ?? "(null)"})");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        _logger.LogTrace("RevokeCertificate called. caRequestId='{CaRequestId}', revocationReason={Reason}",
            caRequestId ?? "(null)", revocationReason);

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestId))
                throw new ArgumentNullException(nameof(caRequestId), "caRequestId cannot be null or empty.");
        });

        _logger.LogDebug("Revoking certificate with ID '{CaRequestId}' for reason {Reason} {Client}",
            caRequestId, revocationReason, this.ToString());

        Item[] certProperties = null;

        await flow.StepAsync("FetchCertificate", async () =>
        {
            certProperties = await Task.Run(() => GetCertificateByTrackingId(caRequestId));
        });

        if (certProperties == null)
        {
            flow.Fail("CertificateNotFound", $"No certificate found for ID '{caRequestId}'");
            _logger.LogError("RevokeCertificate: Certificate with ID '{CaRequestId}' not found", caRequestId);
            throw new Exception($"Certificate with ID {caRequestId} not found");
        }

        string issuer = null;
        string serialNumber = null;
        string reason = null;

        flow.Step("ParseCertificateForRevocation", () =>
        {
            var pem = certProperties.SingleOrDefault(cp => cp.key == "certificate")?.Item1 as string;
            if (string.IsNullOrEmpty(pem))
                throw new Exception($"Certificate PEM is null or empty for ID {caRequestId}");

            var cert = LoadCertificateFromPem(Encoding.ASCII.GetBytes(pem));
            issuer = cert.Issuer;
            // Idnomic revoke API expects the canonical serial form (no leading zeros, lowercase hex).
            // Without this normalization, short (e.g. 1-byte) serials such as "05" are rejected.
            var canonicalSerial = cert.SerialNumber.TrimStart('0').ToLowerInvariant();
            serialNumber = canonicalSerial.Length == 0 ? "0" : canonicalSerial;
            reason = _requestManager.GetRevokeReasonText(revocationReason);

            _logger.LogTrace("RevokeCertificate: Parsed cert. Issuer='{Issuer}', SerialNumber='{Serial}', Reason='{Reason}'",
                issuer, serialNumber, reason);
        });

        await flow.StepAsync("SubmitRevokeRequest", async () =>
        {
            var revokeRequest = _requestManager.GetRevokeRequest(reason, issuer, serialNumber);
            var response = await Task.Run(() => _soapClient.revoke(revokeRequest));

            _logger.LogTrace("RevokeCertificate: SOAP response. Item is {ItemState}, value='{Value}'",
                response?.Message?.Item == null ? "NULL" : response.Message.Item.GetType().Name,
                response?.Message?.Item?.ToString() ?? "(null)");

            if (response?.Message?.Item != null && response.Message.Item as string == "0")
            {
                _logger.LogDebug("Successfully revoked certificate with ID '{CaRequestId}'", caRequestId);
            }
            else
            {
                throw new Exception($"Failed to revoke certificate with ID {caRequestId} - unexpected response");
            }
        });

        _logger.MethodExit(LogLevel.Debug);
    }

    /// <summary>
    /// Retrieves the certificate profiles available in the Idnomic CA.
    /// </summary>
    public List<string> GetTemplates()
    {
        using var flow = new FlowLogger(_logger, "GetTemplates");
        _logger.MethodEntry(LogLevel.Debug);
        EnsureClientIsEnabled();

        _logger.LogDebug("Retrieving certificate profiles from Idnomic service");

        List<string> profiles = null;

        try
        {
            flow.Step("FetchProfiles", () =>
            {
                var request = _requestManager.GetListProfilesRequest();
                var response = _soapClient.list_profiles(request);

                profiles = new List<string>();

                _logger.LogTrace("GetTemplates: SOAP response received. Item is {ItemState}",
                    response?.Message?.Item == null ? "NULL" : "present");

                if (response?.Message?.Item is Item[] items)
                {
                    foreach (var item in items)
                    {
                        if (item?.Item1 is string profileName && !string.IsNullOrEmpty(profileName))
                        {
                            profiles.Add(profileName);
                            _logger.LogTrace("Found profile: '{ProfileName}'", profileName);
                        }
                    }
                }
            });

            _logger.LogDebug("Retrieved {Count} certificate profiles", profiles?.Count ?? 0);
            _logger.MethodExit(LogLevel.Debug);
            return profiles;
        }
        catch (FaultException faultEx)
        {
            flow.Fail("SOAPFault", $"{faultEx.Code} {faultEx.Message}");
            _logger.LogError(faultEx, "SOAP Fault retrieving certificate profiles: Code={Code}, Message={Message}",
                faultEx.Code, faultEx.Message);
            throw new Exception($"Failed to retrieve certificate profiles (SOAP Fault): {faultEx.Message}", faultEx);
        }
        catch (Exception ex)
        {
            flow.Fail("UNHANDLED", ex.Message);
            _logger.LogError(ex, "Error retrieving certificate profiles: {Message}", ex.Message);
            throw new Exception($"Failed to retrieve certificate profiles: {ex.Message}", ex);
        }
    }

    private Item[] GetCertificateByTrackingId(string serialNumber)
    {
        _logger.MethodEntry(LogLevel.Debug);
        _logger.LogTrace("GetCertificateByTrackingId called. serialNumber='{SerialNumber}'", serialNumber ?? "(null)");

        try
        {
            var response = _soapClient.search_for_certificates(_requestManager.GetSearchRequest($"hexserial={serialNumber}", -1));

            _logger.LogTrace("GetCertificateByTrackingId: SOAP response received. Item is {ItemState}",
                response?.Message?.Item == null ? "NULL" : "present");

            if (response?.Message?.Item is Item[] items)
            {
                _logger.LogTrace("GetCertificateByTrackingId: {Count} items in response", items.Length);

                if (items.Length == 1)
                {
                    if (items[0]?.Item1 is Item[] certProperties)
                    {
                        _logger.LogTrace("GetCertificateByTrackingId: Found certificate with {PropCount} properties",
                            certProperties.Length);
                        _logger.MethodExit(LogLevel.Debug);
                        return certProperties;
                    }
                }
                else if (items.Length > 1)
                {
                    _logger.LogWarning("GetCertificateByTrackingId: Expected 1 result but got {Count} for serialNumber='{SerialNumber}'",
                        items.Length, serialNumber);
                }
            }

            _logger.LogTrace("GetCertificateByTrackingId: No matching certificate found for serialNumber='{SerialNumber}'",
                serialNumber ?? "(null)");
            _logger.MethodExit(LogLevel.Debug);
            return null;
        }
        catch (FaultException faultEx)
        {
            _logger.LogError(faultEx, "GetCertificateByTrackingId: SOAP Fault for serialNumber='{SerialNumber}': Code={Code}, Message={Message}",
                serialNumber, faultEx.Code, faultEx.Message);
            throw;
        }
        catch (Exception e)
        {
            _logger.LogError(e, "GetCertificateByTrackingId: Error for serialNumber='{SerialNumber}': {Message}",
                serialNumber ?? "(null)", e.Message);
            throw;
        }
    }

    private List<Item> GetCertificateItems()
    {
        _logger.MethodEntry(LogLevel.Debug);

        try
        {
            _logger.LogTrace("GetCertificateItems: Searching with DN=*|+revocation=*|validAt=");
            var response = _soapClient.search_for_certificates(_requestManager.GetSearchRequest("DN=*|+revocation=*|validAt=", -1));

            _logger.LogTrace("GetCertificateItems: SOAP response received. Item is {ItemState}",
                response?.Message?.Item == null ? "NULL" : "present");

            var itemList = new List<Item>();
            if (response?.Message?.Item is Item[] items)
            {
                itemList.AddRange(items.Where(i => i?.Item1 is Item[]));
                _logger.LogTrace("GetCertificateItems: Extracted {Count} certificate items from {Total} total items",
                    itemList.Count, items.Length);
            }

            _logger.MethodExit(LogLevel.Debug);
            return itemList;
        }
        catch (FaultException faultEx)
        {
            _logger.LogError(faultEx, "GetCertificateItems: SOAP Fault: Code={Code}, Message={Message}",
                faultEx.Code, faultEx.Message);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetCertificateItems: Error: {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Parses the endpoint URL and extracts an issuer DN filter if specified using the ||issuerdnfilter=value suffix syntax.
    /// </summary>
    public static void ParseEndpointAndIssuerFilter(string endpointUrl, out string actualEndpoint, out string issuerDnFilter)
    {
        if (string.IsNullOrEmpty(endpointUrl))
        {
            actualEndpoint = endpointUrl;
            issuerDnFilter = null;
            return;
        }

        const string separator = "||issuerdnfilter=";
        int separatorIndex = endpointUrl.IndexOf(separator, StringComparison.OrdinalIgnoreCase);

        if (separatorIndex >= 0)
        {
            actualEndpoint = endpointUrl.Substring(0, separatorIndex);
            issuerDnFilter = endpointUrl.Substring(separatorIndex + separator.Length);
        }
        else
        {
            actualEndpoint = endpointUrl;
            issuerDnFilter = null;
        }
    }

    /// <summary>
    /// Determines whether a certificate passes the issuer DN filter by checking if the certificate's Issuer DN
    /// contains the filter value (case-insensitive).
    /// </summary>
    private bool PassesIssuerFilter(string pemCertificate)
    {
        if (string.IsNullOrEmpty(_issuerDnFilter))
        {
            return true;
        }

        if (string.IsNullOrEmpty(pemCertificate))
        {
            _logger.LogWarning("PassesIssuerFilter: PEM certificate is null or empty, filtering out");
            return false;
        }

        try
        {
            var cert = LoadCertificateFromPem(Encoding.ASCII.GetBytes(pemCertificate));
            bool passes = cert.Issuer.IndexOf(_issuerDnFilter, StringComparison.OrdinalIgnoreCase) >= 0;

            if (!passes)
            {
                _logger.LogTrace("Certificate with issuer '{Issuer}' filtered out by IssuerDnFilter '{Filter}'",
                    cert.Issuer, _issuerDnFilter);
            }
            else
            {
                _logger.LogTrace("Certificate with issuer '{Issuer}' passed IssuerDnFilter '{Filter}'",
                    cert.Issuer, _issuerDnFilter);
            }

            return passes;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PassesIssuerFilter: Unable to parse certificate for issuer filter check: {Message}", ex.Message);
            return false;
        }
    }

    private static X509Certificate2 LoadCertificateFromPem(byte[] pemBytes)
    {
#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(pemBytes);
#else
        return new X509Certificate2(pemBytes);
#endif
    }

    private static X509Certificate2 LoadCertificateFromFile(string path, string password, X509KeyStorageFlags flags)
    {
#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(path, password, flags);
#else
        return new X509Certificate2(path, password, flags);
#endif
    }

    private void EnsureClientIsEnabled()
    {
        if (!_clientIsEnabled)
        {
            _logger.LogWarning("IdnomicClient is disabled - operation cannot proceed");
            throw new InvalidOperationException("IdnomicClient is disabled. Call Enable() before performing operations.");
        }
    }
}
