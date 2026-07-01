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

using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// The default <see cref="IRegistryAuthenticator"/>: implements the standard OCI distribution
/// authentication loop (attach cached token, send, and on 401 resolve Basic/Bearer, validate the
/// realm, fetch a token, cache it, and retry). It is fully self-contained — it holds its own
/// collaborators and uses only the injected <see cref="RegistryTransport"/> for I/O, so it never
/// touches a <see cref="Client"/> and is unit-testable with a fake transport.
/// </summary>
/// <remarks>
/// This is a design prototype for issue #405. The token-endpoint fetch mirrors <see cref="Client"/>'s
/// existing logic but drives it through the transport; in a full change that logic would move here
/// rather than being duplicated. Non-conformant-registry recovery is a subclass that overrides
/// <see cref="AuthenticateAsync"/> and reuses the protected helpers below — see the tests.
/// </remarks>
public class DefaultRegistryAuthenticator : IRegistryAuthenticator
{
    private const string _defaultClientId = "oras-dotnet";

    private static readonly Lazy<IMemoryCache> _sharedMemoryCache =
        new(() => new MemoryCache(new MemoryCacheOptions { SizeLimit = 1024 }),
            LazyThreadSafetyMode.ExecutionAndPublication);

    private ICache? _cache;

    /// <summary>The token cache. Defaults to a shared in-memory cache.</summary>
    public ICache Cache
    {
        get => _cache ??= new Cache(_sharedMemoryCache.Value);
        init => _cache = value;
    }

    /// <summary>The scope manager used to compute request scopes.</summary>
    public ScopeManager ScopeManager { get; init; } = new();

    /// <summary>Validates realm URLs before credentials are sent to them.</summary>
    public IRealmValidator RealmValidator { get; init; } = new DefaultRealmValidator();

    /// <summary>Optional credential provider.</summary>
    public ICredentialProvider? CredentialProvider { get; init; }

    /// <summary>Optional pre-resolved access-token provider.</summary>
    public IAccessTokenProvider? AccessTokenProvider { get; init; }

    /// <summary>Client id used for OAuth2 token requests.</summary>
    public string? ClientId { get; init; }

    /// <summary>Whether to force OAuth2 (password grant) for username/password credentials.</summary>
    public bool ForceAttemptOAuth2 { get; init; }

    /// <inheritdoc />
    public async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        AuthContext context,
        RegistryTransport transport,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);

        if (request.Headers.Authorization != null)
        {
            return await transport(request, context.AllowAutoRedirect, cancellationToken).ConfigureAwait(false);
        }

        var host = request.RequestUri?.Authority
            ?? throw new ArgumentException("Request URI or its authority is null.", nameof(request));
        var requestedScopes = ScopeManager.GetScopesStringForHost(host);
        var attemptedKey = string.Join(" ", requestedScopes);

        var attempt = await request.CloneAsync(rewindContent: false, cancellationToken).ConfigureAwait(false);
        var attachedCachedToken = TryAttachCachedToken(attempt, host, attemptedKey, context.PartitionId);

        var response = await transport(attempt, context.AllowAutoRedirect, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        var challenge = new AuthChallenge(
            request, response, host, requestedScopes, attachedCachedToken, context.PartitionId);
        try
        {
            var authenticated = await AuthenticateAsync(challenge, context, transport, cancellationToken)
                .ConfigureAwait(false);
            if (authenticated == null)
            {
                // Could not resolve; hand the original 401 back to the caller.
                return response;
            }

            response.Dispose();
            return authenticated;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The single overridable policy: turn a 401 into an authenticated response, or return
    /// <c>null</c> to give up (the caller returns the original 401). The base implementation parses
    /// the challenge and delegates to <see cref="AuthenticateFromChallengeAsync"/>. Override this to
    /// add recovery for non-conformant registries — call <c>base</c>, and on <c>null</c> probe via
    /// <see cref="SendWithoutAuthorizationAsync"/> and re-resolve.
    /// </summary>
    protected virtual Task<HttpResponseMessage?> AuthenticateAsync(
        AuthChallenge challenge,
        AuthContext context,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        var (scheme, parameters) = ParseChallengeSafe(challenge.UnauthorizedResponse);
        return AuthenticateFromChallengeAsync(challenge, scheme, parameters, context, transport, cancellationToken);
    }

    /// <summary>
    /// Standard resolution for a parsed challenge, returning the authenticated response, or
    /// <c>null</c> for an UNUSABLE challenge (no/unknown scheme, or a missing / invalid / disallowed
    /// realm). A credential or token-endpoint failure behind an allowed realm still throws, so a
    /// recovery override can safely treat <c>null</c> as "try to recover" without masking real
    /// credential errors. Because the unit returns a response, the non-throwing composition is
    /// natural — no separate failure-kind result type is needed.
    /// </summary>
    protected async Task<HttpResponseMessage?> AuthenticateFromChallengeAsync(
        AuthChallenge challenge,
        Challenge.Scheme scheme,
        IReadOnlyDictionary<string, string>? parameters,
        AuthContext context,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        switch (scheme)
        {
            case Challenge.Scheme.Basic:
                {
                    var basic = await FetchBasicAsync(challenge.Host, cancellationToken).ConfigureAwait(false);
                    Cache.SetCache(challenge.Host, Challenge.Scheme.Basic, string.Empty, basic, challenge.PartitionId);
                    return await RetryAsync(challenge, context, transport, "Basic", basic, cancellationToken)
                        .ConfigureAwait(false);
                }
            case Challenge.Scheme.Bearer:
                {
                    if (parameters == null)
                    {
                        return null;
                    }

                    var (scopes, newKey) = MergeChallengeScopes(challenge.Host, parameters.GetValueOrDefault("scope"));

                    // Scope-changed cache shortcut: a cached token for the challenged scope is tried
                    // before acquiring a new one. Because the unit returns a response, the
                    // try-then-fall-through is expressed directly (no lossy "resolution").
                    if (newKey != challenge.AttemptedKey &&
                        Cache.TryGetToken(challenge.Host, Challenge.Scheme.Bearer, newKey, out var cachedToken, challenge.PartitionId))
                    {
                        var shortcut = await RetryAsync(challenge, context, transport, "Bearer", cachedToken, cancellationToken)
                            .ConfigureAwait(false);
                        if (shortcut.StatusCode != HttpStatusCode.Unauthorized)
                        {
                            return shortcut;
                        }

                        shortcut.Dispose();
                    }

                    if (!parameters.TryGetValue("realm", out var realm) ||
                        !Uri.TryCreate(realm, UriKind.Absolute, out var realmUri))
                    {
                        return null;
                    }

                    if (!await RealmValidator
                        .IsRealmAllowedAsync(challenge.OriginalRequest.RequestUri!, realmUri, cancellationToken)
                        .ConfigureAwait(false))
                    {
                        return null;
                    }

                    parameters.TryGetValue("service", out var service);
                    var token = await FetchBearerAsync(
                        challenge.Host, realm, service ?? string.Empty, scopes, transport, cancellationToken)
                        .ConfigureAwait(false);
                    Cache.SetCache(challenge.Host, Challenge.Scheme.Bearer, newKey, token, challenge.PartitionId);
                    return await RetryAsync(challenge, context, transport, "Bearer", token, cancellationToken)
                        .ConfigureAwait(false);
                }
            default:
                return null;
        }
    }

    /// <summary>
    /// Re-sends the original request with no <c>Authorization</c> header to elicit a fresh challenge.
    /// The recovery primitive — it is just a call to the transport, so no client façade is needed.
    /// The returned response is owned by the caller and must be disposed.
    /// </summary>
    protected static async Task<HttpResponseMessage> SendWithoutAuthorizationAsync(
        AuthChallenge challenge,
        AuthContext context,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        var cold = await challenge.OriginalRequest.CloneAsync(rewindContent: true, cancellationToken).ConfigureAwait(false);
        cold.Headers.Authorization = null;
        return await transport(cold, context.AllowAutoRedirect, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses the challenge, degrading a malformed one to <see cref="Challenge.Scheme.Unknown"/>.</summary>
    protected static (Challenge.Scheme Scheme, IReadOnlyDictionary<string, string>? Parameters) ParseChallengeSafe(
        HttpResponseMessage response)
    {
        try
        {
            return Challenge.ParseChallenge(response.Headers.WwwAuthenticate.FirstOrDefault()?.ToString());
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return (Challenge.Scheme.Unknown, null);
        }
    }

    private bool TryAttachCachedToken(HttpRequestMessage request, string host, string attemptedKey, string? partitionId)
    {
        if (!Cache.TryGetScheme(host, out var scheme, partitionId))
        {
            return false;
        }

        switch (scheme)
        {
            case Challenge.Scheme.Basic
                when Cache.TryGetToken(host, scheme, string.Empty, out var basic, partitionId):
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
                return true;
            case Challenge.Scheme.Bearer
                when Cache.TryGetToken(host, scheme, attemptedKey, out var bearer, partitionId):
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                return true;
            default:
                return false;
        }
    }

    private (IReadOnlyList<string> Scopes, string CacheKey) MergeChallengeScopes(string host, string? scopeParameter)
    {
        var scopes = new SortedSet<Scope>(ScopeManager.GetScopesForHost(host));
        if (!string.IsNullOrEmpty(scopeParameter))
        {
            foreach (var scopeStr in scopeParameter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (Scope.TryParse(scopeStr, out var scope))
                {
                    Scope.AddOrMergeScope(scopes, scope);
                }
            }
        }

        return (scopes.Select(scope => scope.ToString()).ToList(), string.Join(" ", scopes));
    }

    private static async Task<HttpResponseMessage> RetryAsync(
        AuthChallenge challenge,
        AuthContext context,
        RegistryTransport transport,
        string scheme,
        string token,
        CancellationToken cancellationToken)
    {
        var retry = await challenge.OriginalRequest.CloneAsync(rewindContent: true, cancellationToken).ConfigureAwait(false);
        retry.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        return await transport(retry, context.AllowAutoRedirect, cancellationToken).ConfigureAwait(false);
    }

    private Task<Credential> ResolveCredentialAsync(string host, CancellationToken cancellationToken)
        => CredentialProvider == null
            ? Task.FromResult(CredentialExtensions.EmptyCredential)
            : CredentialProvider.ResolveCredentialAsync(host, cancellationToken);

    private async Task<string> FetchBasicAsync(string host, CancellationToken cancellationToken)
    {
        var credential = await ResolveCredentialAsync(host, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(credential.Username) || string.IsNullOrWhiteSpace(credential.Password))
        {
            throw new AuthenticationException("Missing username or password for basic authentication.");
        }

        return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credential.Username}:{credential.Password}"));
    }

    private async Task<string> FetchBearerAsync(
        string host,
        string realm,
        string service,
        IReadOnlyList<string> scopes,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        if (AccessTokenProvider != null)
        {
            var accessToken = await AccessTokenProvider
                .ResolveAccessTokenAsync(host, realm, service, scopes, forceRefresh: true, cancellationToken)
                .ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                return accessToken;
            }
        }

        var credential = await ResolveCredentialAsync(host, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(credential.AccessToken))
        {
            return credential.AccessToken;
        }

        if (credential.IsEmpty() ||
            (string.IsNullOrWhiteSpace(credential.RefreshToken) && !ForceAttemptOAuth2))
        {
            return await FetchDistributionTokenAsync(
                realm, service, scopes, credential.Username, credential.Password, transport, cancellationToken)
                .ConfigureAwait(false);
        }

        return await FetchOAuth2TokenAsync(realm, service, scopes, credential, transport, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<string> FetchDistributionTokenAsync(
        string realm,
        string service,
        IReadOnlyList<string> scopes,
        string? username,
        string? password,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, realm);
        if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));
        }

        var query = new List<KeyValuePair<string, string>>();
        if (!string.IsNullOrWhiteSpace(service))
        {
            query.Add(new KeyValuePair<string, string>("service", service));
        }

        foreach (var scope in scopes)
        {
            query.Add(new KeyValuePair<string, string>("scope", scope));
        }

        request.RequestUri = new UriBuilder(request.RequestUri!)
        {
            Query = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}")),
        }.Uri;

        using var response = await transport(request, true, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw await response.ParseErrorResponseAsync(cancellationToken).ConfigureAwait(false);
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.TryGetProperty("access_token", out var accessToken) &&
            !string.IsNullOrWhiteSpace(accessToken.GetString()))
        {
            return accessToken.GetString()!;
        }

        if (doc.RootElement.TryGetProperty("token", out var token) &&
            !string.IsNullOrWhiteSpace(token.GetString()))
        {
            return token.GetString()!;
        }

        throw new AuthenticationException("Both AccessToken and Token are empty or missing");
    }

    private async Task<string> FetchOAuth2TokenAsync(
        string realm,
        string service,
        IReadOnlyList<string> scopes,
        Credential credential,
        RegistryTransport transport,
        CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = string.IsNullOrEmpty(ClientId) ? _defaultClientId : ClientId,
        };
        if (!string.IsNullOrWhiteSpace(service))
        {
            form["service"] = service;
        }

        if (!string.IsNullOrEmpty(credential.RefreshToken))
        {
            form["grant_type"] = "refresh_token";
            form["refresh_token"] = credential.RefreshToken;
        }
        else if (!string.IsNullOrEmpty(credential.Username) && !string.IsNullOrEmpty(credential.Password))
        {
            form["grant_type"] = "password";
            form["username"] = credential.Username;
            form["password"] = credential.Password;
        }
        else
        {
            throw new AuthenticationException("missing username or password for bearer auth");
        }

        if (scopes.Count > 0)
        {
            form["scope"] = string.Join(" ", scopes);
        }

        using var content = new FormUrlEncodedContent(form);
        using var request = new HttpRequestMessage(HttpMethod.Post, realm) { Content = content };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(MediaTypeNames.Application.FormUrlEncoded);

        using var response = await transport(request, true, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw await response.ParseErrorResponseAsync(cancellationToken).ConfigureAwait(false);
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.TryGetProperty("access_token", out var accessToken) &&
            !string.IsNullOrEmpty(accessToken.ToString()))
        {
            return accessToken.ToString();
        }

        throw new AuthenticationException("AccessToken is empty or missing");
    }
}
