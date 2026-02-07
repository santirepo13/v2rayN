namespace ServiceLib.Services.CoreConfig;

/// <summary>
/// Persistent proxy assignment with temporary blacklist and rotation on failure.
/// Keyed by an arbitrary target key (e.g., "host:port") to a chosen proxy identifier (e.g., outbound tag).
/// </summary>
public sealed class PersistentProxyService
{
    private static readonly string _tag = nameof(PersistentProxyService);
    private static readonly TimeSpan BlacklistTtl = TimeSpan.FromHours(12);

    private readonly object _lock = new();
    // target -> proxyId
    private readonly Dictionary<string, string> _targetToProxy = new(StringComparer.OrdinalIgnoreCase);
    // proxyId -> blacklisted until
    private readonly Dictionary<string, DateTimeOffset> _blacklistUntil = new(StringComparer.OrdinalIgnoreCase);
    // proxyId -> last used time (LRU aid)
    private readonly Dictionary<string, DateTimeOffset> _lastUsed = new(StringComparer.OrdinalIgnoreCase);

    private readonly System.Timers.Timer _gcTimer;

    private PersistentProxyService()
    {
        _gcTimer = new System.Timers.Timer(TimeSpan.FromMinutes(10).TotalMilliseconds)
        {
            AutoReset = true,
            Enabled = true
        };
        _gcTimer.Elapsed += (_, _) => CleanupExpired();
    }

    private static readonly Lazy<PersistentProxyService> _inst = new(() => new PersistentProxyService());
    public static PersistentProxyService Instance => _inst.Value;

    /// <summary>
    /// Returns the persistently assigned proxy for the target if present; otherwise assigns one
    /// from the provided candidates (excluding blacklisted) and returns it. If all are blacklisted,
    /// picks the least recently used candidate.
    /// </summary>
    /// <param name="targetKey">Target endpoint key (e.g., "api.site.com:443" or "1.2.3.4:443").</param>
    /// <param name="candidates">List of candidate proxy identifiers (e.g., outbound tags).</param>
    /// <returns>Chosen proxy identifier, or empty string if no candidates.</returns>
    public string GetOrAssign(string targetKey, IReadOnlyList<string> candidates)
    {
        if (string.IsNullOrWhiteSpace(targetKey) || candidates is null || candidates.Count == 0)
        {
            return string.Empty;
        }

        lock (_lock)
        {
            CleanupExpired_NoLock();

            if (_targetToProxy.TryGetValue(targetKey, out var pinned) && !IsBlacklisted_NoLock(pinned))
            {
                _lastUsed[pinned] = DateTimeOffset.UtcNow;
                Logging.SaveLog($"{_tag}: Using persistent proxy {pinned} for target {targetKey}");
                return pinned;
            }

            // Filter out blacklisted
            var pool = candidates.Where(c => !IsBlacklisted_NoLock(c)).ToList();
            string selected;
            if (pool.Count > 0)
            {
                // Random among allowed to distribute initial assignments
                selected = pool[Random.Shared.Next(pool.Count)];
            }
            else
            {
                // All blacklisted – pick least recently used to avoid hammering the same exit
                selected = candidates
                    .OrderBy(c => _lastUsed.TryGetValue(c, out var t) ? t : DateTimeOffset.MinValue)
                    .First();
            }

            _targetToProxy[targetKey] = selected;
            _lastUsed[selected] = DateTimeOffset.UtcNow;
            Logging.SaveLog($"{_tag}: Assigned persistent proxy {selected} for target {targetKey}");
            return selected;
        }
    }

    /// <summary>
    /// Reports a connectivity failure for the proxy against the target and rotates the assignment next time.
    /// Adds the proxy to a temporary blacklist for 12 hours.
    /// </summary>
    public void ReportFailure(string targetKey, string proxyId, string reason)
    {
        if (string.IsNullOrWhiteSpace(proxyId)) return;
        lock (_lock)
        {
            var until = DateTimeOffset.UtcNow.Add(BlacklistTtl);
            _blacklistUntil[proxyId] = until;

            if (_targetToProxy.TryGetValue(targetKey, out var current) && string.Equals(current, proxyId, StringComparison.OrdinalIgnoreCase))
            {
                _targetToProxy.Remove(targetKey);
            }

            Logging.SaveLog($"{_tag}: Proxy {proxyId} refused for {targetKey}. Rotating. Blacklisted until {until:O}. Reason: {reason}");
        }
    }

    /// <summary>
    /// Clears the assignment for a target. Does not change blacklist state.
    /// </summary>
    public void ClearTarget(string targetKey)
    {
        lock (_lock)
        {
            _targetToProxy.Remove(targetKey);
        }
    }

    /// <summary>
    /// Removes a proxy from blacklist (e.g., manual unban).
    /// </summary>
    public void Unban(string proxyId)
    {
        if (string.IsNullOrWhiteSpace(proxyId)) return;
        lock (_lock)
        {
            _blacklistUntil.Remove(proxyId);
        }
    }

    /// <summary>
    /// Returns a snapshot of current assignments.
    /// </summary>
    public Dictionary<string, string> SnapshotAssignments()
    {
        lock (_lock)
        {
            return new Dictionary<string, string>(_targetToProxy, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Returns a snapshot of current blacklist with expiry.
    /// </summary>
    public Dictionary<string, DateTimeOffset> SnapshotBlacklist()
    {
        lock (_lock)
        {
            CleanupExpired_NoLock();
            return new Dictionary<string, DateTimeOffset>(_blacklistUntil, StringComparer.OrdinalIgnoreCase);
        }
    }

    private bool IsBlacklisted_NoLock(string proxyId)
    {
        if (_blacklistUntil.TryGetValue(proxyId, out var until))
        {
            if (until <= DateTimeOffset.UtcNow)
            {
                _blacklistUntil.Remove(proxyId);
                return false;
            }
            return true;
        }
        return false;
    }

    private void CleanupExpired()
    {
        lock (_lock)
        {
            CleanupExpired_NoLock();
        }
    }

    private void CleanupExpired_NoLock()
    {
        if (_blacklistUntil.Count == 0) return;
        var now = DateTimeOffset.UtcNow;
        var toRemove = _blacklistUntil.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();
        foreach (var k in toRemove)
        {
            _blacklistUntil.Remove(k);
        }
    }
}

