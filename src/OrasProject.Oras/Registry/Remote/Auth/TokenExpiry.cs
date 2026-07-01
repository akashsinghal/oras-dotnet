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

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// Resolves the absolute expiry used to cache a registry token, applying a fixed precedence:
/// <list type="number">
/// <item>the server-declared expiry (<c>expires_in</c>/<c>issued_at</c> from the token response);</item>
/// <item>the token's JWT <c>exp</c> claim (read without signature validation);</item>
/// <item>a default time-to-live.</item>
/// </list>
/// </summary>
internal static class TokenExpiry
{
    /// <summary>
    /// Resolves the absolute expiry for <paramref name="token"/>.
    /// </summary>
    /// <param name="token">The token to be cached (used only for JWT <c>exp</c> extraction).</param>
    /// <param name="serverExpiresAt">The server-declared expiry, or <c>null</c> if not provided.</param>
    /// <param name="timeProvider">Clock used for the default-TTL fallback.</param>
    /// <param name="defaultTtl">The TTL applied when no expiry can be determined.</param>
    /// <returns>The absolute instant at which the cached token should expire.</returns>
    public static DateTimeOffset Resolve(
        string token,
        DateTimeOffset? serverExpiresAt,
        TimeProvider timeProvider,
        TimeSpan defaultTtl)
    {
        // 1. Server-declared expiry from the token response.
        if (serverExpiresAt is { } expiresAt)
        {
            return expiresAt;
        }

        // 2. JWT 'exp' claim, parsed safely (opaque tokens fall through).
        if (JwtExpiry.TryGetExpiration(token, out var jwtExpiry))
        {
            return jwtExpiry;
        }

        // 3. Default time-to-live.
        return timeProvider.GetUtcNow() + defaultTtl;
    }
}
