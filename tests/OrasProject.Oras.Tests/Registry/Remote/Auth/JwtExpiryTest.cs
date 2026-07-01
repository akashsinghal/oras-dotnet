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
using OrasProject.Oras.Registry.Remote.Auth;
using Xunit;

namespace OrasProject.Oras.Tests.Registry.Remote.Auth;

public class JwtExpiryTest
{
    [Fact]
    public void TryGetExpiration_ValidJwtWithExp_ReturnsExpiration()
    {
        var unix = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var token = AuthTestHelpers.CreateJwt(unix);

        var ok = JwtExpiry.TryGetExpiration(token, out var expiration);

        Assert.True(ok);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(unix), expiration);
    }

    [Fact]
    public void TryGetExpiration_JwtWithoutExpClaim_ReturnsFalse()
    {
        var token = AuthTestHelpers.CreateJwt(null);

        Assert.False(JwtExpiry.TryGetExpiration(token, out var expiration));
        Assert.Equal(default, expiration);
    }

    [Theory]
    [InlineData("opaque-token-value")]
    [InlineData("only.two")]
    [InlineData("not-a-jwt")]
    public void TryGetExpiration_OpaqueOrMalformedToken_ReturnsFalse(string token)
    {
        Assert.False(JwtExpiry.TryGetExpiration(token, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TryGetExpiration_EmptyOrWhitespace_ReturnsFalse(string token)
    {
        Assert.False(JwtExpiry.TryGetExpiration(token, out _));
    }

    [Fact]
    public void TryGetExpiration_OversizedToken_ReturnsFalse()
    {
        var token = new string('a', 70 * 1024);

        Assert.False(JwtExpiry.TryGetExpiration(token, out _));
    }
}
