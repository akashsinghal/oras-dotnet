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
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// Safely extracts the expiration (<c>exp</c> claim) from a JWT access token <b>without validating
/// its signature, issuer, or audience</b>. The token originates from an upstream registry and is
/// treated as untrusted input: it is only read to determine a cache time-to-live, never to make a
/// security decision. Any malformed, opaque, or oversized input yields <c>false</c> rather than
/// throwing.
/// </summary>
internal static class JwtExpiry
{
    /// <summary>
    /// Upper bound on the token size accepted for parsing. Registry access tokens are well under
    /// this; the bound caps work performed on maliciously oversized input.
    /// </summary>
    private const int MaxJwtSizeInBytes = 64 * 1024;

    // JwtSecurityTokenHandler is thread-safe for reading; shared to avoid per-call allocation.
    private static readonly JwtSecurityTokenHandler _handler = new()
    {
        MaximumTokenSizeInBytes = MaxJwtSizeInBytes,
    };

    /// <summary>
    /// Attempts to read the <c>exp</c> claim of a JWT and return it as an absolute UTC instant.
    /// </summary>
    /// <param name="token">
    /// The candidate token. Opaque (non-JWT) tokens are expected and yield <c>false</c>.
    /// </param>
    /// <param name="expiration">The parsed expiry on success; otherwise <c>default</c>.</param>
    /// <returns>
    /// <c>true</c> if <paramref name="token"/> is a JWT with a parseable <c>exp</c> claim;
    /// otherwise <c>false</c> (opaque token, missing/invalid <c>exp</c>, oversized, or malformed).
    /// </returns>
    public static bool TryGetExpiration(string token, out DateTimeOffset expiration)
    {
        expiration = default;
        if (string.IsNullOrWhiteSpace(token) || !_handler.CanReadToken(token))
        {
            // Opaque/non-JWT tokens are a normal case, not an error.
            return false;
        }

        try
        {
            var jwt = _handler.ReadJwtToken(token);
            if (jwt.ValidTo == DateTime.MinValue)
            {
                // No 'exp' claim present in the payload.
                return false;
            }

            // JwtSecurityToken.ValidTo is UTC; make the kind explicit for DateTimeOffset.
            expiration = new DateTimeOffset(DateTime.SpecifyKind(jwt.ValidTo, DateTimeKind.Utc));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (SecurityTokenException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
