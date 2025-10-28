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
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.Idnomic.Client;

/// <summary>
/// <see cref="IIdnomicClient"/> exposes standard methods for the operations required by a full-featured AnyCA Gateway REST plugin.
/// </summary>
public interface IIdnomicClient
{
    /// <summary>
    /// Pings the CA to ensure it is reachable using the underlying authentication and connection information.
    /// Always returns if the CA is reachable or if the client is not enabled by the <see cref="Enable"/> method.
    /// </summary>
    /// <returns></returns>
    Task ValidateConnection();

    /// <summary>
    /// Enables the client to perform operations against the CA.
    /// </summary>
    /// <returns>
    /// Always returns a <see cref="Task"/>.
    /// </returns>
    Task Enable();

    /// <summary>
    /// Disables the client from performing operations against the CA.
    /// </summary>
    /// <returns>
    /// Always returns a <see cref="Task"/>.
    /// </returns>
    Task Disable();

    /// <summary>
    /// Returns the current enabled state of the <see cref="IIdnomicClient"/>.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the client is enabled; otherwise, <see langword="false"/>.
    /// </returns>
    bool IsEnabled();

    /// <summary>
    /// Retrieves the certificate profiles available in the Idnomic CA. 
    /// </summary>
    /// <returns>
    /// A <see cref="List{T}"/> of <see cref="string"/> containing the available certificate profile names.
    /// </returns>
    List<string> GetTemplates();

    /// <summary>
    /// Downloads a certificate with the specified <paramref name="caRequestId"/> in PEM format and stores it in a <see cref="AnyCAPluginCertificate"/>.
    /// </summary>
    /// <param name="caRequestId">
    /// The CA Request ID (serial number) of the certificate to download.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as a <see cref="AnyCAPluginCertificate"/> containing the downloaded certificate.
    /// </returns>
    Task<AnyCAPluginCertificate> DownloadCertificate(string caRequestId);

    /// <summary>
    /// Downloads all certificates issued by the CA and stores them in a <see cref="BlockingCollection{T}"/>.
    /// </summary>
    /// <param name="certificatesBuffer">
    /// The <see cref="BlockingCollection{T}"/> to store the downloaded certificates.
    /// </param>
    /// <param name="cancelToken">
    /// The <see cref="CancellationToken"/> to cancel the operation.
    /// </param>
    /// <param name="issuedAfter">
    /// Optional parameter to filter certificates issued after a specific date/time.
    /// </param>
    /// <returns>
    /// Returns a <see cref="Task"/> and task result as an <see cref="int"/> containing the number of downloaded certificates.
    /// </returns>
    Task<int> DownloadAllIssuedCertificates(BlockingCollection<AnyCAPluginCertificate> certificatesBuffer, CancellationToken cancelToken, DateTime? issuedAfter = null);

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
    Task<EnrollmentResult> Enroll(string csr, string productId, string zone, CancellationToken cancelToken);

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
    Task RevokeCertificate(string caRequestId, uint revocationReason);
}