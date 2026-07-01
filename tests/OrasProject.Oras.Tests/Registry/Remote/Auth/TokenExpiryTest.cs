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

public class TokenExpiryTest
{
    private static readonly DateTimeOffset _now = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Resolve_ServerExpiresAtProvided_TakesPrecedenceOverJwt()
    {
        var serverExpiresAt = _now.AddMinutes(10);
        // The token carries a different (earlier) exp to prove the server value wins.
        var token = AuthTestHelpers.CreateJwt(_now.AddMinutes(1).ToUnixTimeSeconds());

        var result = TokenExpiry.Resolve(
            token, serverExpiresAt, new FixedTimeProvider(_now), TimeSpan.FromMinutes(5));

        Assert.Equal(serverExpiresAt, result);
    }

    [Fact]
    public void Resolve_NoServerExpiry_UsesJwtExp()
    {
        var unix = _now.AddMinutes(30).ToUnixTimeSeconds();
        var token = AuthTestHelpers.CreateJwt(unix);

        var result = TokenExpiry.Resolve(
            token, null, new FixedTimeProvider(_now), TimeSpan.FromMinutes(5));

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(unix), result);
    }

    [Fact]
    public void Resolve_NoServerExpiryAndOpaqueToken_UsesDefaultTtl()
    {
        var defaultTtl = TimeSpan.FromMinutes(5);

        var result = TokenExpiry.Resolve(
            "opaque-token", null, new FixedTimeProvider(_now), defaultTtl);

        Assert.Equal(_now + defaultTtl, result);
    }
}
