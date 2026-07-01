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
/// The outcome of fetching a token from a registry authentication endpoint: the token itself and,
/// when the endpoint declared one, the absolute expiry derived from the token response.
/// </summary>
/// <param name="Token">The access (bearer) token, or the base64 <c>username:password</c> for Basic.</param>
/// <param name="ExpiresAt">
/// The server-declared absolute expiry — computed as <c>issued_at + expires_in</c> per the
/// distribution token spec — or <c>null</c> when the response did not include a usable
/// <c>expires_in</c>. When <c>null</c>, callers fall back to the token's JWT <c>exp</c> claim and
/// then to a default time-to-live.
/// </param>
public sealed record TokenResult(string Token, DateTimeOffset? ExpiresAt);
