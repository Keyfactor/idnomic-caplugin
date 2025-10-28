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
    ILogger _logger = LogHandler.GetClassLogger<IdnomicCAPlugin>();
    ICertificateDataReader _certificateDataReader;
    IIdnomicClient Client { get; set; }
    private bool _idnomicClientWasInjected = false;

    public IdnomicCAPlugin()
    {
        // Explicit default constructor
    }

    public IdnomicCAPlugin(IIdnomicClient client)
    {
        _logger.MethodEntry();
        Client = client;
        _idnomicClientWasInjected = true;
        _logger.MethodExit();
    }

    public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
    {
        _logger.MethodEntry();
        _certificateDataReader = certificateDataReader;
        IdnomicClientFromCAConnectionData(configProvider.CAConnectionData);
        _logger.MethodExit();
    }

    public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
    {
        _logger.MethodEntry();
        _logger.MethodExit();
        return IdnomicPluginConfig.GetPluginAnnotations();
    }

    public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        _logger.MethodEntry();
        _logger.MethodExit();
        return IdnomicPluginConfig.GetTemplateParameterAnnotations();
    }

    public List<string> GetProductIds()
    {
        _logger.MethodEntry();
        _logger.MethodExit();
        return Client.GetTemplates();
    }

    public async Task Ping()
    {
        _logger.MethodEntry();
        if (!Client.IsEnabled())
        {
            _logger.LogDebug("IdnomicClient is disabled. Skipping Ping");
            return;
        }
        _logger.LogDebug("Pinging Idnomic CA to validate connection");
        await Client.ValidateConnection();
        _logger.MethodExit();
    }

    public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
    {
        _logger.MethodEntry();
        IdnomicClientFromCAConnectionData(connectionInfo);
        _logger.MethodExit();
        return Ping();
    }

    public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
    {
        _logger.MethodEntry();

        // Validate that Zone parameter is present
        if (productInfo.ProductParameters == null ||
            !productInfo.ProductParameters.ContainsKey(IdnomicPluginConfig.EnrollmentParametersConstants.Zone) ||
            string.IsNullOrWhiteSpace(productInfo.ProductParameters[IdnomicPluginConfig.EnrollmentParametersConstants.Zone]))
        {
            throw new ArgumentException($"Required parameter '{IdnomicPluginConfig.EnrollmentParametersConstants.Zone}' is missing or empty");
        }

        _logger.MethodExit();
        return Task.CompletedTask;
    }

    public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
    {
        _logger.MethodEntry();
        if (fullSync && lastSync != null)
        {
            _logger.LogInformation("Performing a full CA synchronization");
            lastSync = null;
        }
        else
        {
            _logger.LogInformation($"Performing an incremental CA synchronization - downloading certificates issued after {lastSync}");
        }

        int certificates = await Client.DownloadAllIssuedCertificates(blockingBuffer, cancelToken, lastSync);
        _logger.LogDebug($"Synchronized {certificates} certificates");
        _logger.MethodExit();
    }

    public Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
    {
        _logger.MethodEntry();
        _logger.MethodExit();
        return Client.DownloadCertificate(caRequestID);
    }

    public Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
    {
        _logger.MethodEntry();

        if (requestFormat != RequestFormat.PKCS10)
        {
            throw new Exception($"Unsupported CSR format: {requestFormat}");
        }

        string zone = productInfo.ProductParameters[IdnomicPluginConfig.EnrollmentParametersConstants.Zone];

        _logger.MethodExit();
        return Client.Enroll(csr, productInfo.ProductID, zone, CancellationToken.None);
    }

    public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
    {
        _logger.MethodEntry();
        _logger.LogDebug($"Revoking certificate with request ID: {caRequestID}");

        await Client.RevokeCertificate(caRequestID, revocationReason);

        _logger.MethodExit();
        return (int)EndEntityStatus.REVOKED;
    }

    private void IdnomicClientFromCAConnectionData(Dictionary<string, object> connectionData)
    {
        _logger.MethodEntry();
        _logger.LogDebug($"Validating Idnomic CA Connection properties");
        var rawData = JsonSerializer.Serialize(connectionData);
        IdnomicPluginConfig.Config config = JsonSerializer.Deserialize<IdnomicPluginConfig.Config>(rawData);

        _logger.LogTrace($"IdnomicClientFromCAConnectionData - EndpointAddress: {config.EndpointAddress}");
        _logger.LogTrace($"IdnomicClientFromCAConnectionData - ClientCertificateLocation: {config.ClientCertificateLocation}");
        _logger.LogTrace($"IdnomicClientFromCAConnectionData - Enabled: {config.Enabled}");

        List<string> missingFields = new List<string>();

        if (string.IsNullOrEmpty(config.EndpointAddress)) missingFields.Add(nameof(config.EndpointAddress));
        if (string.IsNullOrEmpty(config.ClientCertificateLocation)) missingFields.Add(nameof(config.ClientCertificateLocation));
        if (string.IsNullOrEmpty(config.ClientCertificatePassword)) missingFields.Add(nameof(config.ClientCertificatePassword));

        if (config.Enabled && missingFields.Count > 0)
        {
            throw new ArgumentException($"The following required fields are missing or empty: {string.Join(", ", missingFields)}");
        }

        if (_idnomicClientWasInjected && Client != null)
        {
            _logger.LogDebug("Not building an IdnomicClient - one was injected");
        }
        else
        {
            _logger.LogDebug("Creating new IdnomicClient instance.");
            Client = new IdnomicClient(config.EndpointAddress, config.ClientCertificateLocation, config.ClientCertificatePassword);
        }

        if (config.Enabled)
        {
            Client.Enable();
        }
        else
        {
            Client.Disable();
        }
        _logger.MethodExit();
    }
}