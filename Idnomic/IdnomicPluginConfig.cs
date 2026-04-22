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

using System.Collections.Generic;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.Idnomic;

public class IdnomicPluginConfig
{
    public class ConfigConstants
    {
        public const string EndpointAddress = "EndpointAddress";
        public const string ClientCertLocation = "ClientCertLocation";
        public const string ClientCertPassword = "ClientCertPassword";
        public const string Enabled = "Enabled";
        public const string IssuerDnFilter = "IssuerDnFilter";
    }

    public class Config
    {
        public string EndpointAddress { get; set; }
        public string ClientCertLocation { get; set; }
        public string ClientCertPassword { get; set; }
        public bool Enabled { get; set; }
        public string IssuerDnFilter { get; set; }
    }

    public static class EnrollmentParametersConstants
    {
        public const string Zone = "Zone";
    }

    public static Dictionary<string, PropertyConfigInfo> GetPluginAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>()
        {
            [ConfigConstants.EndpointAddress] = new PropertyConfigInfo()
            {
                Comments = "The SOAP endpoint address for the Idnomic RA service. For example, 'https://idnomic-server.com/ra-service'.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.ClientCertLocation] = new PropertyConfigInfo()
            {
                Comments = "The file path to the client certificate used for mutual TLS authentication with the Idnomic service.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
            [ConfigConstants.ClientCertPassword] = new PropertyConfigInfo()
            {
                Comments = "The password for the client certificate.",
                Hidden = true,
                DefaultValue = "",
                Type = "Secret"
            },
            [ConfigConstants.Enabled] = new PropertyConfigInfo()
            {
                Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available.",
                Hidden = false,
                DefaultValue = true,
                Type = "Boolean"
            },
            [ConfigConstants.IssuerDnFilter] = new PropertyConfigInfo()
            {
                Comments = "Optional filter to restrict certificate synchronization to a specific issuing CA. Only certificates whose Issuer DN contains this value (case-insensitive) will be synchronized. For example, 'CN=MySubCA' will match any certificate issued by a CA whose DN contains that string. Can also be specified as a suffix on the endpoint URL using ||issuerdnfilter=<value> syntax.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
        };
    }

    public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
    {
        return new Dictionary<string, PropertyConfigInfo>()
        {
            [EnrollmentParametersConstants.Zone] = new PropertyConfigInfo()
            {
                Comments = "The Idnomic zone identifier for certificate enrollment. This parameter is required for enrollment operations.",
                Hidden = false,
                DefaultValue = "",
                Type = "String"
            },
        };
    }
}