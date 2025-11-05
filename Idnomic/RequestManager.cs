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
using System.IO;
using Keyfactor.AnyGateway.IdnomicCaProxy.IdnomicRaService;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.CAPlugin.Idnomic.Client;

public class RequestManager
{
    ILogger _logger = LogHandler.GetClassLogger<RequestManager>();

    public static Func<string, string> Pemify = ss =>
        ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

    public int MapReturnStatus(string idnomicStatus)
    {
        try
        {
            _logger.MethodEntry();
            _logger.LogTrace($"idnomicStatus is {idnomicStatus}");
            EndEntityStatus returnStatus;

            switch (idnomicStatus)
            {
                case "V":
                    returnStatus = EndEntityStatus.GENERATED;
                    break;
                case "Initial":
                case "PENDING":
                    returnStatus = EndEntityStatus.NEW;
                    break;
                case "R":
                    returnStatus = EndEntityStatus.REVOKED;
                    break;
                default:
                    returnStatus = EndEntityStatus.FAILED;
                    break;
            }
            _logger.LogTrace($"returnStatus is {returnStatus}");
            _logger.MethodExit();
            return (int)returnStatus;
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in MapReturnStatus: {e.Message}");
            throw;
        }
    }

    public string GetRevokeReasonText(uint revokeReason)
    {
        try
        {
            _logger.MethodEntry();
            _logger.LogTrace($"Revoke Reason {revokeReason}");
            switch (revokeReason)
            {
                case 3:
                    return "affiliationChanged";
                case 5:
                    return "cessationOfOperation";
                case 1:
                    return "keyCompromise";
                case 4:
                    return "superseded";
                default:
                    return "unspecified";
            }
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in GetRevokeReasonText: {e.Message}");
            throw;
        }
    }

    public OTMessageType GetListProfilesRequest()
    {
        try
        {
            _logger.MethodEntry();

            // Empty array for list_profiles - no parameters needed
            var itemArray = new Item[0];

            var msg = new AnyGateway.IdnomicCaProxy.IdnomicRaService.Message
            {
                ItemElementName = ItemChoiceType.Array,
                Item = itemArray
            };

            var msgType = new OTMessageType { Message = msg };

            _logger.MethodExit();
            return msgType;
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in GetListProfilesRequest: {e.Message}");
            throw;
        }
    }

    public OTMessageType GetRevokeRequest(string reason, string issuer, string serialNumber)
    {
        try
        {
            _logger.MethodEntry();
            _logger.LogTrace($"Reason: {reason}, Issuer: {issuer}, serialNumber: {serialNumber}");
            Item[] itemArray = new Item[3];

            var i1 = new Item { key = "reason", Item1ElementName = Item1ChoiceType.Value, Item1 = reason };
            var i2 = new Item { key = "issuer", Item1ElementName = Item1ChoiceType.Value, Item1 = issuer };
            var i3 = new Item { key = "serial", Item1ElementName = Item1ChoiceType.Value, Item1 = serialNumber };

            itemArray[0] = i1;
            itemArray[1] = i2;
            itemArray[2] = i3;

            var msg = new AnyGateway.IdnomicCaProxy.IdnomicRaService.Message { ItemElementName = ItemChoiceType.HashTable, Item = itemArray };

            var msgType = new OTMessageType { Message = msg };
            _logger.MethodExit();
            return msgType;
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in GetRevokeRequest: {e.Message}");
            throw;
        }
    }

    public OTMessageType GetSearchRequest(string searchString, int pageSize)
    {
        try
        {
            _logger.MethodEntry();
            _logger.LogTrace($"searchString: {searchString}, pageSize: {pageSize}");
            Item[] itemArray = new Item[3];

            Item[] filterArray = new Item[searchString.Split('|').Length];
            var i = 0;
            foreach (var filterItem in searchString.Split('|'))
            {
                var parts = filterItem.Split('=');
                var f1 = new Item { Item1ElementName = Item1ChoiceType.Value, Item1 = parts.Length > 1 ? parts[1] : "", key = parts[0] };
                filterArray[i] = f1;
                i++;
            }

            var i1 = new Item { key = "filter", Item1ElementName = Item1ChoiceType.HashTable, Item1 = filterArray };
            var i2 = new Item { key = "distinct", Item1ElementName = Item1ChoiceType.Value, Item1 = "1" };
            var i3 = new Item { key = "limit", Item1ElementName = Item1ChoiceType.Value, Item1 = pageSize.ToString() };

            itemArray[0] = i1;
            itemArray[1] = i2;
            itemArray[2] = i3;

            var msg = new AnyGateway.IdnomicCaProxy.IdnomicRaService.Message { ItemElementName = ItemChoiceType.HashTable, Item = itemArray };

            var msgType = new OTMessageType { Message = msg };
            _logger.MethodExit();
            return msgType;
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in GetSearchRequest: {e.Message}");
            throw;
        }
    }

    public OTMessageType GetEnrollRequest(string csr, string profile, string zone)
    {
        try
        {
            _logger.MethodEntry();
            _logger.LogTrace($"csr: {csr}");
            var pemCert = Pemify(csr);
            _logger.LogTrace($"pemCert Intermediate: {pemCert}");
            pemCert = "-----BEGIN CERTIFICATE REQUEST-----\n" + pemCert;
            pemCert += "\n-----END CERTIFICATE REQUEST-----";
            _logger.LogTrace($"pemCertFinal: {pemCert}");

            var sr = new StringReader(pemCert);
            var reader = new PemReader(sr);
            var req = reader.ReadObject() as Pkcs10CertificationRequest;
            var info = req?.GetCertificationRequestInfo();
            var subject = info?.Subject.ToString();

            var itemArray = new Item[6];
            var i1 = new Item { key = "countryName1", Item1ElementName = Item1ChoiceType.Value, Item1 = GetValueFromCsr("C", subject) };
            var i2 = new Item { key = "adminEmail1", Item1ElementName = Item1ChoiceType.Value, Item1 = GetValueFromCsr("E", subject) };
            var i3 = new Item { key = "zone", Item1ElementName = Item1ChoiceType.Value, Item1 = zone };
            var i4 = new Item { key = "organizationName1", Item1ElementName = Item1ChoiceType.Value, Item1 = GetValueFromCsr("O", subject) };
            var i5 = new Item { key = "pkcs10", Item1ElementName = Item1ChoiceType.Value, Item1 = pemCert };
            var i6 = new Item { key = "commonName1", Item1ElementName = Item1ChoiceType.Value, Item1 = GetValueFromCsr("CN", subject) };

            _logger.LogTrace($"i1 = {i1}");
            _logger.LogTrace($"i2 = {i2}");
            _logger.LogTrace($"i3 = {i3}");
            _logger.LogTrace($"i4 = {i4}");
            _logger.LogTrace($"i5 = {i5}");
            _logger.LogTrace($"i6 = {i6}");

            itemArray[0] = i1;
            itemArray[1] = i2;
            itemArray[2] = i3;
            itemArray[3] = i4;
            itemArray[4] = i5;
            itemArray[5] = i6;

            var h1 = new Item { Item1ElementName = Item1ChoiceType.HashTable, Item1 = itemArray, key = "1" };

            Item[] itemArrayTwo = new Item[2];

            var i7 = new Item { key = "0", Item1ElementName = Item1ChoiceType.Value, Item1 = profile };

            _logger.LogTrace($"h1 = {h1}");
            _logger.LogTrace($"i7 = {i7}");

            itemArrayTwo[0] = i7;
            itemArrayTwo[1] = h1;

            var msg = new AnyGateway.IdnomicCaProxy.IdnomicRaService.Message { ItemElementName = ItemChoiceType.Array, Item = itemArrayTwo };

            var msgType = new OTMessageType { Message = msg };
            _logger.MethodExit();
            return msgType;
        }
        catch (Exception e)
        {
            _logger.LogError($"Exception Occurred in GetEnrollRequest: {e.Message}");
            throw;
        }
    }

    public string GetValueFromCsr(string subjectItem, string csr)
    {
        try
        {
            _logger.MethodEntry();
            if (string.IsNullOrEmpty(csr))
            {
                _logger.MethodExit();
                return "";
            }

            var csrValues = csr.Split(',');
            foreach (var val in csrValues)
            {
                var nmValPair = val.Trim().Split('=');
                if (nmValPair.Length == 2 && subjectItem == nmValPair[0].Trim())
                {
                    _logger.MethodExit();
                    return nmValPair[1].Trim();
                }
            }
            _logger.MethodExit();
            return "";
        }
        catch (Exception e)
        {
            _logger.LogError($"Error in GetValueFromCsr: {e.Message}");
            throw;
        }
    }
}