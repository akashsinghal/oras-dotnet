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

using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using OrasProject.Oras.Registry.Remote.Auth;
using Xunit;

namespace OrasProject.Oras.Tests.Registry.Remote.Auth;

/// <summary>
/// Prototype tests for the <see cref="IRegistryAuthenticator"/> shape (issue #405). Every test drives
/// the authenticator through a plain <see cref="RegistryTransport"/> delegate — there is no
/// <see cref="Client"/> and no <see cref="HttpClient"/> anywhere — which is the composability the
/// current <c>IAuthChallengeHandler</c> design cannot offer (its context is bound to a live client).
/// </summary>
public class RegistryAuthenticatorPrototypeTest
{
    private const string _staleToken = "stale_token";
    private const string _freshToken = "fresh_token";

    // A fake transport: a pure function from request to response. No sockets, no client.
    private static RegistryTransport Transport(Func<HttpRequestMessage, HttpResponseMessage> registry)
        => (request, allowAutoRedirect, cancellationToken) => Task.FromResult(registry(request));

    private static HttpResponseMessage Ok() => new(HttpStatusCode.OK);

    private static HttpResponseMessage Token(string token) =>
        new(HttpStatusCode.OK) { Content = new StringContent($"{{\"token\":\"{token}\"}}") };

    private static HttpResponseMessage Bearer(string wwwAuthenticate)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", wwwAuthenticate));
        return response;
    }

    private static HttpResponseMessage NoChallenge() => new(HttpStatusCode.Unauthorized);

    [Fact]
    public async Task Default_BearerDistributionFlow_NeedsNoClientOrHttpClient()
    {
        const string host = "registry.example.com";
        HttpResponseMessage Registry(HttpRequestMessage req)
        {
            if (req.RequestUri!.AbsolutePath == "/token")
            {
                return Token(_freshToken);
            }

            return req.Headers.Authorization?.Parameter == _freshToken
                ? Ok()
                : Bearer($"realm=\"https://{host}/token\",service=\"{host}\"");
        }

        // Construct the authenticator directly — no Client, no HttpClient.
        var authenticator = new DefaultRegistryAuthenticator();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/v2/");

        var response = await authenticator.SendAsync(
            request, new AuthContext(), Transport(Registry), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Recovering_StaleToken401_WithNoChallenge_Recovers()
    {
        const string host = "registry-omits-challenge.example.com";
        HttpResponseMessage Registry(HttpRequestMessage req)
        {
            if (req.RequestUri!.AbsolutePath == "/token")
            {
                return Token(_freshToken);
            }

            return req.Headers.Authorization?.Parameter switch
            {
                _freshToken => Ok(),
                _staleToken => NoChallenge(),
                _ => Bearer($"realm=\"https://{host}/token\",service=\"{host}\""),
            };
        }

        var authenticator = new RecoveringRegistryAuthenticator();
        authenticator.Cache.SetCache(host, Challenge.Scheme.Bearer, string.Empty, _staleToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/v2/");

        var response = await authenticator.SendAsync(
            request, new AuthContext(), Transport(Registry), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Recovering_StaleToken401_WithForeignRealm_Recovers()
    {
        const string host = "registry-foreign-realm.example.com";
        const string foreignIdp = "idp.example.com";
        HttpResponseMessage Registry(HttpRequestMessage req)
        {
            if (req.RequestUri!.AbsolutePath == "/proxy_auth")
            {
                return Token(_freshToken);
            }

            return req.Headers.Authorization?.Parameter switch
            {
                _freshToken => Ok(),
                _staleToken => Bearer($"realm=\"https://{foreignIdp}/token\",service=\"{host}\""),
                _ => Bearer($"realm=\"https://{host}/proxy_auth\",service=\"{host}\""),
            };
        }

        var authenticator = new RecoveringRegistryAuthenticator();
        authenticator.Cache.SetCache(host, Challenge.Scheme.Bearer, string.Empty, _staleToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/v2/");

        var response = await authenticator.SendAsync(
            request, new AuthContext(), Transport(Registry), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Default_StaleToken401_WithNoChallenge_DoesNotRecover()
    {
        const string host = "registry-omits-challenge-default.example.com";
        HttpResponseMessage Registry(HttpRequestMessage req)
            => req.Headers.Authorization?.Parameter == _staleToken
                ? NoChallenge()
                : Bearer($"realm=\"https://{host}/token\",service=\"{host}\"");

        var authenticator = new DefaultRegistryAuthenticator();
        authenticator.Cache.SetCache(host, Challenge.Scheme.Bearer, string.Empty, _staleToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/v2/");

        var response = await authenticator.SendAsync(
            request, new AuthContext(), Transport(Registry), CancellationToken.None);

        // The default authenticator surfaces the unusable 401 — recovery is opt-in via a subclass.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Recovering_StaleToken401_AnonymousResource_ReturnsColdSuccess()
    {
        // A public resource whose only problem is the stale cached token: the cold, no-auth request
        // succeeds. Recovery must return that success, not the original stale-token 401.
        const string host = "registry-anonymous.example.com";
        HttpResponseMessage Registry(HttpRequestMessage req)
            => req.Headers.Authorization?.Parameter == _staleToken ? NoChallenge() : Ok();

        var authenticator = new RecoveringRegistryAuthenticator();
        authenticator.Cache.SetCache(host, Challenge.Scheme.Bearer, string.Empty, _staleToken);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/v2/");

        var response = await authenticator.SendAsync(
            request, new AuthContext(), Transport(Registry), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// Recovery composed as a ~10-line subclass of the default authenticator: it reuses the protected
    /// base helpers, needs no <see cref="Client"/>, and introduces no new context surface. On an
    /// unusable challenge it probes without credentials and re-resolves from the fresh challenge.
    /// </summary>
    private sealed class RecoveringRegistryAuthenticator : DefaultRegistryAuthenticator
    {
        protected override async Task<HttpResponseMessage?> AuthenticateAsync(
            AuthChallenge challenge,
            AuthContext context,
            RegistryTransport transport,
            CancellationToken cancellationToken)
        {
            var response = await base.AuthenticateAsync(challenge, context, transport, cancellationToken);
            if (response != null)
            {
                return response;
            }

            if (!challenge.AttachedCachedToken || !challenge.CanReplay)
            {
                return null;
            }

            var cold = await SendWithoutAuthorizationAsync(challenge, context, transport, cancellationToken);
            if (cold.StatusCode != HttpStatusCode.Unauthorized)
            {
                // The request succeeds without credentials (e.g. an anonymous resource whose only
                // problem was the stale token) — hand that response back rather than the stale 401.
                return cold;
            }

            var (scheme, parameters) = ParseChallengeSafe(cold);
            cold.Dispose();
            return await AuthenticateFromChallengeAsync(
                challenge, scheme, parameters, context, transport, cancellationToken);
        }
    }
}
