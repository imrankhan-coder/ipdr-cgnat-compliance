-- Dashboard stats cache: expensive aggregates computed in the background every
-- 60s so the dashboard reads instantly instead of scanning 24h of translations.
-- One row per scope: scope_key = 'all' or 'nas:<id>'.
CREATE TABLE IF NOT EXISTS dashboard_stats_cache (
    scope_key     text PRIMARY KEY,          -- 'all' | 'nas:4' | 'nas:6' ...
    nat_total     bigint,                    -- estimate (partition reltuples)
    nat_24h       bigint,
    nat_1h        bigint,
    subs_online   integer,                   -- from ppp_sessions
    unique_ips    integer,
    chart_json    jsonb,                      -- [{hour, cnt}, ...] for the 24h chart
    computed_at   timestamp without time zone NOT NULL DEFAULT now()
);
