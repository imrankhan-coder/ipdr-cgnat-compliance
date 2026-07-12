-- Analytics long-range cache. Stores the fully-computed analytics payload
-- (all template variables) as JSON, keyed by scope + range. Refreshed every
-- 5 min by analytics_refresh.py. Only long ranges (12h/24h/1w/1M) are cached;
-- short ranges compute live. NMS-style periodic rollup for historical stats.
CREATE TABLE IF NOT EXISTS analytics_cache (
    scope_key   text NOT NULL,          -- 'all' | 'nas:4' ...
    range_key   text NOT NULL,          -- '12h' | '24h' | '1w' | '1M'
    payload     jsonb NOT NULL,         -- {stats, protocols, top_apps, ...}
    computed_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_key, range_key)
);
