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

namespace OrasProject.Oras.Registry.Remote.Auth;

/// <summary>
/// The per-request context an <see cref="IRegistryAuthenticator"/> needs beyond the request itself.
/// This is plain data — it carries no client references or capabilities.
/// </summary>
public sealed class AuthContext
{
    /// <summary>
    /// Optional cache partition identifier, isolating cached tokens per credential set.
    /// </summary>
    public string? PartitionId { get; init; }

    /// <summary>
    /// Whether the request (and its auth retries) should follow redirects.
    /// </summary>
    public bool AllowAutoRedirect { get; init; } = true;
}
