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

using System.Collections.Generic;
using System.Net.Http;

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// Immutable description of a 401 (Unauthorized) exchange, handed to the standard-resolution and
/// recovery hooks of <see cref="DefaultRegistryAuthenticator"/>. It is plain data — no client
/// references, no capabilities. The authenticator supplies I/O via the injected
/// <see cref="RegistryTransport"/> instead.
/// </summary>
public sealed class AuthChallenge
{
    /// <summary>Initializes a new instance.</summary>
    public AuthChallenge(
        HttpRequestMessage originalRequest,
        HttpResponseMessage unauthorizedResponse,
        string host,
        IReadOnlyList<string> requestedScopes,
        bool attachedCachedToken,
        string? partitionId)
    {
        OriginalRequest = originalRequest;
        UnauthorizedResponse = unauthorizedResponse;
        Host = host;
        RequestedScopes = requestedScopes;
        AttachedCachedToken = attachedCachedToken;
        PartitionId = partitionId;
    }

    /// <summary>The original request (no <c>Authorization</c> header set).</summary>
    public HttpRequestMessage OriginalRequest { get; }

    /// <summary>The 401 response, including its <c>WWW-Authenticate</c> challenge.</summary>
    public HttpResponseMessage UnauthorizedResponse { get; }

    /// <summary>The registry authority (host[:port]).</summary>
    public string Host { get; }

    /// <summary>The scopes computed for <see cref="Host"/> before this challenge.</summary>
    public IReadOnlyList<string> RequestedScopes { get; }

    /// <summary>Whether the failed attempt carried a cached token (a stale-token-rejection hint).</summary>
    public bool AttachedCachedToken { get; }

    /// <summary>The cache partition identifier for the request, if any.</summary>
    public string? PartitionId { get; }

    /// <summary>The cache scope key the failed attempt used.</summary>
    public string AttemptedKey => string.Join(" ", RequestedScopes);

    /// <summary>Whether the original request can be safely re-sent (an idempotent GET/HEAD).</summary>
    public bool CanReplay =>
        OriginalRequest.Method == HttpMethod.Get ||
        OriginalRequest.Method == HttpMethod.Head;
}
