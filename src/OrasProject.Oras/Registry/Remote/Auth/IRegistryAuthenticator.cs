// Copyright The ORAS Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// Produces an authenticated response for a registry request. This is the pluggable unit for
/// authentication: it owns the entire attach-token → send → 401 → resolve → retry loop, so response
/// handling lives in one place and consumers can compose or replace the whole behavior.
/// </summary>
/// <remarks>
/// <para>
/// Unlike a "given a 401, return a token" hook, an authenticator takes the raw request and the
/// <see cref="RegistryTransport"/> and returns the final response. It never references a
/// <see cref="Client"/>: the transport is its only outbound capability, so a credential-free probe
/// is simply a call to the transport, and the whole thing is unit-testable with a fake transport.
/// </para>
/// <para>
/// The default, <see cref="DefaultRegistryAuthenticator"/>, implements the standard OCI flow.
/// Recovery for non-conformant registries is a subclass (or decorator) of the default, not a new
/// context surface.
/// </para>
/// </remarks>
public interface IRegistryAuthenticator
{
    /// <summary>
    /// Sends <paramref name="request"/> through <paramref name="transport"/>, performing any
    /// authentication handshake, and returns the resulting response.
    /// </summary>
    /// <param name="request">The request to authenticate and send. Must not have an <c>Authorization</c> header.</param>
    /// <param name="context">Per-request data (partition, redirect policy).</param>
    /// <param name="transport">The capability used to send requests (including a credential-free probe).</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The authenticated response, or the original 401 if authentication could not be resolved.</returns>
    Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        AuthContext context,
        RegistryTransport transport,
        CancellationToken cancellationToken = default);
}
