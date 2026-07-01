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
using Microsoft.Extensions.Caching.Memory;

namespace OrasProject.Oras.Registry.Remote.Auth;

public sealed class Cache : ICache
{
    #region private members
    /// <summary>
    /// The underlying memory cache used to store authentication schemes and tokens.
    /// </summary>
    private readonly IMemoryCache _memoryCache;

    /// <summary>
    /// Prefix for scheme cache keys to prevent collisions with other users of the same memory cache.
    /// </summary>
    private const string _schemeKeyPrefix = "ORAS_AUTH_SCHEME_";

    /// <summary>
    /// Prefix for token cache keys. Each token is stored as its own entry so the memory cache can
    /// evict it independently the moment it expires.
    /// </summary>
    private const string _tokenKeyPrefix = "ORAS_AUTH_TOKEN_";

    /// <summary>
    /// Default cache entry options with size=1.
    /// These options are used when user-provided options are null.
    /// </summary>
    private static readonly MemoryCacheEntryOptions _defaultCacheEntryOptions = new()
    {
        Size = 1 // always set size to ensure size limits work properly
    };

    /// <summary>
    /// Builds the scheme cache key for a registry (optionally partitioned).
    /// Uses pipe (|) as delimiter since it cannot appear in registry hostnames.
    /// </summary>
    private static string GetSchemeKey(string registry, string? partitionId) =>
        string.IsNullOrEmpty(partitionId)
            ? $"{_schemeKeyPrefix}{registry}"
            : $"{_schemeKeyPrefix}{partitionId}|{registry}";

    /// <summary>
    /// Builds the token cache key for a registry/scheme/scope (optionally partitioned).
    /// The scheme is part of the key so tokens for different schemes never collide.
    /// </summary>
    private static string GetTokenKey(
        string registry,
        Challenge.Scheme scheme,
        string scopeKey,
        string? partitionId)
    {
        var partitionPrefix = string.IsNullOrEmpty(partitionId) ? string.Empty : $"{partitionId}|";
        return $"{_tokenKeyPrefix}{partitionPrefix}{registry}|{(int)scheme}|{scopeKey}";
    }
    #endregion

    /// <summary>
    /// Creates a new Cache instance with the specified memory cache.
    /// </summary>
    /// <param name="memoryCache">The underlying memory cache to use for storage.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="memoryCache"/> is null.
    /// </exception>
    public Cache(IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
    }

    /// <summary>
    /// Cache entry options used in SetCache for configuring token caching behavior.
    /// If not set, default options with size=1 are used.
    /// </summary>
    /// <remarks>
    /// Note: If the underlying memory cache has a size limit configured, you should
    /// always set the <see cref="MemoryCacheEntryOptions.Size"/> property on your custom
    /// options to ensure proper cache eviction behavior.
    /// </remarks>
    public MemoryCacheEntryOptions? CacheEntryOptions { get; set; }

    /// <summary>
    /// TryGetScheme attempts to retrieve the authentication scheme associated with the specified
    /// registry host.
    /// </summary>
    /// <param name="registry">The registry host (e.g., "docker.io").</param>
    /// <param name="scheme">
    /// When this method returns, contains the <see cref="Challenge.Scheme"/> associated with the
    /// registry if found in the cache; otherwise, <see cref="Challenge.Scheme.Unknown"/>.
    /// </param>
    /// <param name="partitionId">
    /// Optional cache partition identifier. When provided, tokens are isolated by this ID,
    /// enabling multi-partition scenarios where different credentials are used for the same registry.
    /// </param>
    /// <returns>
    /// <c>true</c> if the authentication scheme was found in the cache; otherwise, <c>false</c>.
    /// </returns>
    public bool TryGetScheme(string registry, out Challenge.Scheme scheme, string? partitionId = null)
    {
        if (_memoryCache.TryGetValue(GetSchemeKey(registry, partitionId), out Challenge.Scheme cachedScheme))
        {
            scheme = cachedScheme;
            return true;
        }

        scheme = Challenge.Scheme.Unknown;
        return false;
    }

    /// <summary>
    /// Sets or updates the cache for a specific registry, authentication scheme, and scope.
    /// </summary>
    /// <param name="registry">The registry host (e.g., "docker.io").</param>
    /// <param name="scheme">The authentication scheme associated with the cache entry.</param>
    /// <param name="scopeKey">
    /// The OAuth2 scope key used to identify the token within the cache.
    /// </param>
    /// <param name="token">The token to be stored in the cache.</param>
    /// <param name="expiresAt">
    /// The absolute instant at which the token entry should expire. When provided, the underlying
    /// memory cache evicts the token automatically once this instant passes. When <c>null</c>
    /// (e.g., for Basic credentials), the token does not expire on a timer.
    /// </param>
    /// <param name="partitionId">
    /// Optional cache partition identifier. When provided, tokens are isolated by this ID,
    /// enabling multi-partition scenarios where different credentials are used for the same registry.
    /// </param>
    /// <remarks>
    /// <para>
    /// The scheme is stored as its own long-lived entry, and each token is stored as a separate
    /// entry keyed by registry, scheme, and scope. This lets the memory cache expire individual
    /// tokens on their own schedule without dropping the scheme or other still-valid tokens.
    /// </para>
    /// <para>
    /// This method uses the <see cref="MemoryCacheEntryOptions.Size"/> from
    /// <see cref="CacheEntryOptions"/> if set, or falls back to size=1. Setting the size ensures
    /// proper cache eviction behavior when the underlying cache has a size limit configured.
    /// </para>
    /// </remarks>
    public void SetCache(
        string registry,
        Challenge.Scheme scheme,
        string scopeKey,
        string token,
        DateTimeOffset? expiresAt = null,
        string? partitionId = null)
    {
        var entryOptions = CacheEntryOptions ?? _defaultCacheEntryOptions;

        // The scheme is long-lived and lightweight; store it as a size-free entry so that token
        // expiry never drops it (which would force a re-challenge) and it doesn't consume the
        // caller's size budget.
        _memoryCache.Set(
            GetSchemeKey(registry, partitionId),
            scheme,
            new MemoryCacheEntryOptions { Size = 0 });

        // The token entry inherits the caller's configured options (size, callbacks, sliding/absolute
        // expiration). A supplied token expiry takes precedence over any configured absolute expiration.
        _memoryCache.Set(
            GetTokenKey(registry, scheme, scopeKey, partitionId),
            token,
            BuildTokenEntryOptions(entryOptions, expiresAt));
    }

    /// <summary>
    /// Builds the memory cache options for a token entry by cloning the caller-configured
    /// <see cref="CacheEntryOptions"/> and, when a token expiry is supplied, applying it as the
    /// authoritative absolute expiration.
    /// </summary>
    private static MemoryCacheEntryOptions BuildTokenEntryOptions(
        MemoryCacheEntryOptions source,
        DateTimeOffset? expiresAt)
    {
        var options = new MemoryCacheEntryOptions
        {
            Size = source.Size ?? 1,
            Priority = source.Priority,
            SlidingExpiration = source.SlidingExpiration,
            AbsoluteExpiration = source.AbsoluteExpiration,
            AbsoluteExpirationRelativeToNow = source.AbsoluteExpirationRelativeToNow,
        };

        foreach (var callback in source.PostEvictionCallbacks)
        {
            options.PostEvictionCallbacks.Add(callback);
        }

        foreach (var expirationToken in source.ExpirationTokens)
        {
            options.ExpirationTokens.Add(expirationToken);
        }

        if (expiresAt.HasValue)
        {
            options.AbsoluteExpiration = expiresAt.Value;
            options.AbsoluteExpirationRelativeToNow = null;
        }

        return options;
    }

    /// <summary>
    /// TryGetToken attempts to retrieve a token from the cache for the specified registry,
    /// scheme, and scope key.
    /// </summary>
    /// <param name="registry">The registry host (e.g., "docker.io").</param>
    /// <param name="scheme">The authentication scheme associated with the token.</param>
    /// <param name="scopeKey">
    /// The OAuth2 scope key used to identify the token within the cache.
    /// </param>
    /// <param name="token">
    /// When this method returns, contains the token associated with the specified registry,
    /// scheme, and scope key, if found; otherwise, an empty string.
    /// </param>
    /// <param name="partitionId">
    /// Optional cache partition identifier. When provided, tokens are isolated by this ID,
    /// enabling multi-partition scenarios where different credentials are used for the same registry.
    /// </param>
    /// <returns>
    /// <c>true</c> if a token matching the specified registry, scheme, and scope key is found;
    /// otherwise, <c>false</c>.
    /// </returns>
    public bool TryGetToken(
        string registry,
        Challenge.Scheme scheme,
        string scopeKey,
        out string token,
        string? partitionId = null)
    {
        // An expired token entry is evicted by the memory cache and read here as a miss,
        // which causes the caller to acquire a fresh token.
        if (_memoryCache.TryGetValue(GetTokenKey(registry, scheme, scopeKey, partitionId), out string? cachedToken) &&
            cachedToken != null)
        {
            token = cachedToken;
            return true;
        }

        token = string.Empty;
        return false;
    }
}
