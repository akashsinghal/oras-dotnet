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
/// Sends an HTTP request and returns its response, choosing whether to follow redirects. This is
/// the only capability an <see cref="IRegistryAuthenticator"/> needs from its host — it decouples
/// the authenticator from any particular <see cref="Client"/> or <see cref="HttpClient"/>, so a
/// unit test can supply a fake transport and no real network or client is required.
/// </summary>
/// <param name="request">The request to send.</param>
/// <param name="allowAutoRedirect">
/// Whether redirects should be followed. Passing this per call lets the authenticator use a
/// redirect-following transport for token endpoints and a non-following one for blob-location
/// capture, without the two-<see cref="HttpClient"/> coupling a message-handler chain would impose.
/// </param>
/// <param name="cancellationToken">A token to cancel the operation.</param>
/// <returns>The HTTP response.</returns>
public delegate Task<HttpResponseMessage> RegistryTransport(
    HttpRequestMessage request,
    bool allowAutoRedirect,
    CancellationToken cancellationToken);
