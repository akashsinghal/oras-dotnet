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
using System.Text;

namespace OrasProject.Oras.Tests.Registry.Remote.Auth;

/// <summary>
/// Shared helpers for authentication token cache tests.
/// </summary>
internal static class AuthTestHelpers
{
    /// <summary>
    /// Builds an (unsigned) JWT string whose payload carries the given <paramref name="expUnixSeconds"/>
    /// as the <c>exp</c> claim (omitted when null). The token is not signed — it exists only to exercise
    /// expiry extraction, which does not validate signatures.
    /// </summary>
    public static string CreateJwt(long? expUnixSeconds)
    {
        var header = Base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        var payloadJson = expUnixSeconds.HasValue
            ? $"{{\"exp\":{expUnixSeconds.Value},\"sub\":\"test\"}}"
            : "{\"sub\":\"test\"}";
        var payload = Base64Url(payloadJson);
        var signature = Base64Url("signature");
        return $"{header}.{payload}.{signature}";
    }

    private static string Base64Url(string value)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

/// <summary>
/// A <see cref="TimeProvider"/> whose current UTC time is fixed and settable, for deterministic tests.
/// </summary>
internal sealed class FixedTimeProvider : TimeProvider
{
    public FixedTimeProvider(DateTimeOffset utcNow) => UtcNow = utcNow;

    public DateTimeOffset UtcNow { get; set; }

    public override DateTimeOffset GetUtcNow() => UtcNow;
}
