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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.Idnomic.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.Idnomic;

public class IdnomicCAPlugin : IAnyCAPlugin
{
    private readonly ILogger _logger;
    ICertificateDataReader _certificateDataReader;
    IIdnomicClient Client { get; set; }
    private bool _idnomicClientWasInjected = false;

    public IdnomicCAPlugin()
    {
        _logger = LogHandler.GetClassLogger<IdnomicCAPlugin>();
    }

    public IdnomicCAPlugin(IIdnomicClient client)
    {
        _logger = LogHandler.GetClassLogger<IdnomicCAPlugin>();
        _logger.MethodEntry(LogLevel.Debug);
        Client = client;
        _idnomicClientWasInjected = true;
        _logger.LogTrace("IdnomicCAPlugin constructed with injected client. Client is {ClientState}",
            client == null ? "NULL" : "present");
        _logger.MethodExit(LogLevel.Debug);
    }

    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        using var flow = new FlowLogger(_logger, "Initialize");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("Initialize called. configProvider is {ConfigState}, certificateDataReader is {ReaderState}",
            configProvider == null ? "NULL" : "present",
            certificateDataReader == null ? "NULL" : "present");

        flow.Step("ValidateInputs", () =>
        {
            if (configProvider == null)
                throw new ArgumentNullException(nameof(configProvider), "configProvider cannot be null.");
            if (certificateDataReader == null)
                throw new ArgumentNullException(nameof(certificateDataReader), "certificateDataReader cannot be null.");
        });

        flow.Step("StoreCertificateDataReader", () =>
        {
            _certificateDataReader = certificateDataReader;
        });

        flow.Step("BuildClientFromConnectionData", () =>
        {
            IdnomicClientFromCAConnectionData(configProvider.CAConnectionData);
        });

        _logger.MethodExit(LogLevel.Debug);
    }

    public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
    {
        _logger.MethodEntry(LogLevel.Debug);
        var annotations = IdnomicPluginConfig.GetPluginAnnotations();
        _logger.LogTrace("Returning {Count} CA connector annotations", annotations.Count);
        _logger.MethodExit(LogLevel.Debug);
        return annotations;
    }

    public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        _logger.MethodEntry(LogLevel.Debug);

        var annotations = IdnomicPluginConfig.GetTemplateParameterAnnotations();

        _logger.LogDebug("Returning {Count} static template parameter annotations", annotations.Count);
        _logger.MethodExit(LogLevel.Debug);
        return annotations;
    }

    public List<string> GetProductIds()
    {
        using var flow = new FlowLogger(_logger, "GetProductIds");
        _logger.MethodEntry(LogLevel.Debug);

        List<string> templates = null;

        flow.Step("FetchTemplatesFromCA", () =>
        {
            templates = Client.GetTemplates();
        });

        _logger.LogDebug("Retrieved {Count} templates from CA", templates?.Count ?? 0);
        _logger.MethodExit(LogLevel.Debug);
        return templates;
    }

    public async Task Ping()
    {
        using var flow = new FlowLogger(_logger, "Ping");
        _logger.MethodEntry();

        if (!Client.IsEnabled())
        {
            flow.Skip("ValidateConnection", "Client is disabled");
            _logger.LogDebug("IdnomicClient is disabled. Skipping Ping");
            _logger.MethodExit();
            return;
        }

        _logger.LogDebug("Pinging Idnomic CA to validate connection");

        try
        {
            await flow.StepAsync("ValidateConnection", async () =>
            {
                await Client.ValidateConnection();
            });
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            _logger.LogError(inner, "Ping: AggregateException: {Message}", inner?.Message ?? ae.Message);
            throw new Exception($"Ping failed: {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            _logger.LogError(e, "Ping: Exception: {Message}", e.Message);
            throw;
        }

        _logger.MethodExit();
    }

    public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
        using var flow = new FlowLogger(_logger, "ValidateCAConnectionInfo");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("ValidateCAConnectionInfo called. connectionInfo is {State}, key count={Count}",
            connectionInfo == null ? "NULL" : "present",
            connectionInfo?.Count ?? 0);

        flow.Step("ValidateInputs", () =>
        {
            if (connectionInfo == null)
                throw new ArgumentNullException(nameof(connectionInfo), "connectionInfo cannot be null.");
        });

        flow.Step("BuildClientFromConnectionData", () =>
        {
            IdnomicClientFromCAConnectionData(connectionInfo);
        });

        _logger.MethodExit(LogLevel.Debug);
        return Ping();
    }

    public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
    {
        using var flow = new FlowLogger(_logger, "ValidateProductInfo");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("ValidateProductInfo called. productInfo is {ProdState}, connectionInfo is {ConnState}",
            productInfo == null ? "NULL" : "present",
            connectionInfo == null ? "NULL" : "present");

        flow.Step("ValidateInputs", () =>
        {
            if (productInfo == null)
                throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null.");

            if (productInfo.ProductParameters == null ||
                !productInfo.ProductParameters.ContainsKey(IdnomicPluginConfig.EnrollmentParametersConstants.Zone) ||
                string.IsNullOrWhiteSpace(productInfo.ProductParameters[IdnomicPluginConfig.EnrollmentParametersConstants.Zone]))
            {
                throw new ArgumentException("Zone parameter is required");
            }
        });

        _logger.LogDebug("Product info validated for template '{ProductId}'", productInfo.ProductID ?? "(null)");
        _logger.MethodExit(LogLevel.Debug);
        return Task.CompletedTask;
    }

    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
    {
        var syncType = fullSync ? "Full" : "Incremental";
        using var flow = new FlowLogger(_logger, $"Synchronize-{syncType}");
        _logger.MethodEntry();

        _logger.LogTrace("Synchronize called. blockingBuffer is {BufferState}, lastSync={LastSync}, fullSync={FullSync}",
            blockingBuffer == null ? "NULL" : "present",
            lastSync?.ToString("o") ?? "(null)",
            fullSync);

        flow.Step("ValidateInputs", () =>
        {
            if (blockingBuffer == null)
                throw new ArgumentNullException(nameof(blockingBuffer), "blockingBuffer cannot be null.");
        });

        if (fullSync && lastSync != null)
        {
            _logger.LogInformation("Performing a full CA synchronization");
            lastSync = null;
        }
        else
        {
            _logger.LogInformation("Performing an incremental CA synchronization - downloading certificates issued after {LastSync}",
                lastSync?.ToString("o") ?? "(null)");
        }

        int certificates = 0;
        try
        {
            await flow.StepAsync("DownloadAllIssuedCertificates", async () =>
            {
                certificates = await Client.DownloadAllIssuedCertificates(blockingBuffer, cancelToken, lastSync);
            }, $"lastSync={lastSync?.ToString("o") ?? "(null)"}");

            flow.Step("SyncComplete", $"Synchronized {certificates} certificates");
            _logger.LogDebug("Synchronized {Count} certificates", certificates);
        }
        catch (OperationCanceledException)
        {
            flow.Fail("Cancelled", "operation was cancelled");
            _logger.LogWarning("Synchronize: operation was cancelled.");
            if (!blockingBuffer.IsAddingCompleted)
                blockingBuffer.CompleteAdding();
            throw;
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            _logger.LogError(inner, "Synchronize: AggregateException: {Message}", inner?.Message ?? ae.Message);
            throw new Exception($"Synchronize failed: {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            _logger.LogError(e, "Synchronize: Exception: {Message}", e.Message);
            throw;
        }

        _logger.MethodExit();
    }

    public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        using var flow = new FlowLogger(_logger, $"GetSingleRecord({caRequestID ?? "(null)"})");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("GetSingleRecord called. caRequestID='{CaRequestId}'", caRequestID ?? "(null)");

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestID))
                throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty.");
        });

        AnyCAPluginCertificate certificate = null;

        try
        {
            await flow.StepAsync("DownloadCertificate", async () =>
            {
                certificate = await Client.DownloadCertificate(caRequestID);
            });

            if (certificate == null)
            {
                flow.Fail("ParseResponse", "Client returned null");
                _logger.LogWarning("GetSingleRecord: DownloadCertificate returned null for caRequestID='{CaRequestId}'", caRequestID);
                _logger.MethodExit(LogLevel.Debug);
                return new AnyCAPluginCertificate
                {
                    CARequestID = caRequestID,
                };
            }

            _logger.LogTrace("GetSingleRecord: certificate retrieved. CARequestID='{CaRequestId}', HasCert={HasCert}, Status={Status}",
                certificate.CARequestID ?? "(null)",
                !string.IsNullOrEmpty(certificate.Certificate),
                certificate.Status);
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            _logger.LogError(inner, "GetSingleRecord: AggregateException for caRequestID='{CaRequestId}': {Message}",
                caRequestID, inner?.Message ?? ae.Message);
            throw new Exception($"Error getting single cert for '{caRequestID}': {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            _logger.LogError(e, "GetSingleRecord: Exception for caRequestID='{CaRequestId}': {Message}", caRequestID, e.Message);
            throw new Exception($"Error getting single cert for '{caRequestID}': {e.Message}", e);
        }

        _logger.MethodExit(LogLevel.Debug);
        return certificate;
    }

    public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        using var flow = new FlowLogger(_logger, $"Enroll-{enrollmentType}");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("Enroll called. csr is {CsrState}, subject='{Subject}', productInfo is {ProdState}, requestFormat={Format}, enrollmentType={Type}",
            string.IsNullOrEmpty(csr) ? "NULL/empty" : $"present ({csr.Length} chars)",
            subject ?? "(null)",
            productInfo == null ? "NULL" : "present",
            requestFormat,
            enrollmentType);

        string zone = null;

        flow.Step("ValidateInputs", () =>
        {
            if (string.IsNullOrEmpty(csr))
                throw new ArgumentException("CSR cannot be null or empty.", nameof(csr));

            if (productInfo == null)
                throw new ArgumentNullException(nameof(productInfo), "productInfo cannot be null.");

            if (requestFormat != RequestFormat.PKCS10)
                throw new Exception($"Unsupported CSR format: {requestFormat}");

            if (productInfo.ProductParameters == null ||
                !productInfo.ProductParameters.ContainsKey(IdnomicPluginConfig.EnrollmentParametersConstants.Zone))
            {
                throw new ArgumentException("Zone parameter is required");
            }

            zone = productInfo.ProductParameters[IdnomicPluginConfig.EnrollmentParametersConstants.Zone];
            if (string.IsNullOrWhiteSpace(zone))
                throw new ArgumentException("Zone parameter cannot be empty.");
        });

        _logger.LogDebug("Enrolling certificate with ProductID='{ProductId}', Zone='{Zone}'", productInfo.ProductID ?? "(null)", zone ?? "(null)");

        EnrollmentResult result = null;

        try
        {
            await flow.StepAsync("SubmitEnrollment", async () =>
            {
                result = await Client.Enroll(csr, productInfo.ProductID, zone, CancellationToken.None);
            });

            if (result == null)
            {
                flow.Fail("ParseResponse", "Client returned null");
                _logger.LogError("Enroll: Client.Enroll returned null for ProductID='{ProductId}'", productInfo.ProductID ?? "(null)");
                _logger.MethodExit(LogLevel.Debug);
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = "Enrollment failed - client returned null response"
                };
            }

            _logger.LogTrace("Enroll: result received. Status={Status}, CARequestID='{CaRequestId}', StatusMessage='{Message}'",
                result.Status,
                result.CARequestID ?? "(null)",
                result.StatusMessage ?? "(null)");
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            _logger.LogError(inner, "Enroll: AggregateException: {Message}", inner?.Message ?? ae.Message);
            _logger.MethodExit(LogLevel.Debug);
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Enrollment failed: {inner?.Message ?? ae.Message}"
            };
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            _logger.LogError(e, "Enroll: Exception: {Message}", e.Message);
            _logger.MethodExit(LogLevel.Debug);
            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.FAILED,
                StatusMessage = $"Enrollment failed: {e.Message}"
            };
        }

        _logger.MethodExit(LogLevel.Debug);
        return result;
    }

    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        using var flow = new FlowLogger(_logger, $"Revoke({caRequestID ?? "(null)"})");
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("Revoke called. caRequestID='{CaRequestId}', hexSerialNumber='{HexSerial}', revocationReason={Reason}",
            caRequestID ?? "(null)",
            hexSerialNumber ?? "(null)",
            revocationReason);

        flow.Step("ValidateInput", () =>
        {
            if (string.IsNullOrEmpty(caRequestID))
                throw new ArgumentNullException(nameof(caRequestID), "caRequestID cannot be null or empty.");
        });

        try
        {
            await flow.StepAsync("RevokeCertificate", async () =>
            {
                await Client.RevokeCertificate(caRequestID, revocationReason);
            });

            _logger.LogDebug("Successfully revoked certificate with request ID='{CaRequestId}'", caRequestID);
        }
        catch (AggregateException ae)
        {
            var inner = ae.Flatten().InnerException;
            flow.Fail("UNHANDLED", inner?.Message ?? ae.Message);
            _logger.LogError(inner, "Revoke: AggregateException for caRequestID='{CaRequestId}': {Message}",
                caRequestID, inner?.Message ?? ae.Message);
            throw new Exception($"Revoke failed for '{caRequestID}': {inner?.Message ?? ae.Message}", inner ?? ae);
        }
        catch (Exception e)
        {
            flow.Fail("UNHANDLED", e.Message);
            _logger.LogError(e, "Revoke: Exception for caRequestID='{CaRequestId}': {Message}", caRequestID, e.Message);
            throw new Exception($"Revoke failed for '{caRequestID}': {e.Message}", e);
        }

        _logger.MethodExit(LogLevel.Debug);
        return (int)EndEntityStatus.REVOKED;
    }

    private void IdnomicClientFromCAConnectionData(Dictionary<string, object> connectionData)
    {
        _logger.MethodEntry(LogLevel.Debug);

        _logger.LogTrace("IdnomicClientFromCAConnectionData called. connectionData is {State}, key count={Count}",
            connectionData == null ? "NULL" : "present",
            connectionData?.Count ?? 0);

        if (connectionData == null)
            throw new ArgumentNullException(nameof(connectionData), "connectionData cannot be null.");

        _logger.LogDebug("Validating Idnomic CA Connection properties");
        var rawData = JsonSerializer.Serialize(connectionData);
        IdnomicPluginConfig.Config config = JsonSerializer.Deserialize<IdnomicPluginConfig.Config>(rawData);

        if (config == null)
            throw new InvalidOperationException("Failed to deserialize CA connection data into Config object.");

        _logger.LogTrace("IdnomicClientFromCAConnectionData - EndpointAddress: {Endpoint}",
            config.EndpointAddress ?? "(null)");
        _logger.LogTrace("IdnomicClientFromCAConnectionData - ClientCertificateLocation: {CertLocation}",
            config.ClientCertLocation ?? "(null)");
        _logger.LogTrace("IdnomicClientFromCAConnectionData - Enabled: {Enabled}", config.Enabled);
        _logger.LogTrace("IdnomicClientFromCAConnectionData - IssuerDnFilter: {Filter}",
            config.IssuerDnFilter ?? "(null)");

        List<string> missingFields = new List<string>();

        if (string.IsNullOrEmpty(config.EndpointAddress)) missingFields.Add(nameof(config.EndpointAddress));
        if (string.IsNullOrEmpty(config.ClientCertLocation)) missingFields.Add(nameof(config.ClientCertLocation));
        if (string.IsNullOrEmpty(config.ClientCertPassword)) missingFields.Add(nameof(config.ClientCertPassword));

        if (config.Enabled && missingFields.Count > 0)
        {
            _logger.LogError("Required fields are missing: {MissingFields}", string.Join(", ", missingFields));
            throw new ArgumentException($"The following required fields are missing or empty: {string.Join(", ", missingFields)}");
        }

        if (_idnomicClientWasInjected && Client != null)
        {
            _logger.LogDebug("Not building an IdnomicClient - one was injected");
        }
        else
        {
            // Parse the endpoint URL for an embedded issuer DN filter (||issuerdnfilter=value syntax)
            IdnomicClient.ParseEndpointAndIssuerFilter(config.EndpointAddress, out string actualEndpoint, out string endpointIssuerFilter);

            _logger.LogTrace("ParseEndpointAndIssuerFilter result: actualEndpoint='{Endpoint}', endpointIssuerFilter='{Filter}'",
                actualEndpoint ?? "(null)",
                endpointIssuerFilter ?? "(null)");

            // The dedicated config field takes precedence; fall back to the endpoint-embedded filter
            string issuerDnFilter = !string.IsNullOrEmpty(config.IssuerDnFilter) ? config.IssuerDnFilter : endpointIssuerFilter;

            if (!string.IsNullOrEmpty(issuerDnFilter))
            {
                _logger.LogDebug("Issuer DN filter resolved to: '{IssuerDnFilter}'", issuerDnFilter);
            }
            else
            {
                _logger.LogTrace("No issuer DN filter configured - all certificates will be synchronized");
            }

            _logger.LogDebug("Creating new IdnomicClient instance with endpoint='{Endpoint}'", actualEndpoint ?? "(null)");
            Client = new IdnomicClient(actualEndpoint, config.ClientCertLocation, config.ClientCertPassword, issuerDnFilter);
        }

        if (config.Enabled)
        {
            _logger.LogDebug("Enabling IdnomicClient");
            Client.Enable();
        }
        else
        {
            _logger.LogDebug("Disabling IdnomicClient");
            Client.Disable();
        }

        _logger.MethodExit(LogLevel.Debug);
    }
}
