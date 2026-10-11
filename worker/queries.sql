-- Behaviour queries over access_log. Run with:
--   npx wrangler d1 execute workshop-audit --remote --file=queries.sql
-- (or paste one at a time with --command). Timestamps are unix ms.

-- 1. Per-attendee overview: spread of activity, page vs bulk kinds, distinct devices.
SELECT attendee_id,
       datetime(MIN(ts) / 1000, 'unixepoch') AS first_seen,
       datetime(MAX(ts) / 1000, 'unixepoch') AS last_seen,
       COUNT(DISTINCT date(ts / 1000, 'unixepoch')) AS active_days,
       SUM(kind = 'page')                    AS pages,
       COUNT(DISTINCT CASE WHEN kind = 'page' THEN path END) AS distinct_pages,
       SUM(kind IN ('pdf', 'json'))          AS downloads,
       SUM(kind IN ('print', 'search', 'feed')) AS bulk_views,
       COUNT(DISTINCT ip_hash)               AS ips,
       COUNT(DISTINCT ua)                    AS user_agents,
       SUM(status IN (401, 403))             AS denied
FROM access_log
WHERE attendee_id IS NOT NULL AND kind != 'join'
GROUP BY attendee_id
ORDER BY downloads + bulk_views DESC;

-- 2. Smash-and-grab: 10-minute windows with many distinct gated paths.
SELECT attendee_id,
       datetime((ts / 600000) * 600, 'unixepoch') AS window_start,
       COUNT(DISTINCT path) AS distinct_paths,
       SUM(kind IN ('pdf', 'json')) AS downloads,
       SUM(bytes) AS bytes
FROM access_log
WHERE status = 200 AND kind != 'asset'
GROUP BY attendee_id, ts / 600000
HAVING distinct_paths >= 20
ORDER BY distinct_paths DESC;

-- 3. Downloads with no page referer (scripted fetch or a pasted link list).
SELECT attendee_id, datetime(ts / 1000, 'unixepoch') AS at, path, ua
FROM access_log
WHERE kind IN ('pdf', 'json') AND status = 200 AND (referer IS NULL OR referer = '')
ORDER BY ts;

-- 4. Non-browser user agents.
SELECT attendee_id, ua, COUNT(*) AS hits
FROM access_log
WHERE ua = '' OR ua LIKE '%wget%' OR ua LIKE '%curl%' OR ua LIKE '%python%' OR ua LIKE '%httrack%' OR ua LIKE '%go-http%'
GROUP BY attendee_id, ua
ORDER BY hits DESC;

-- 5. Link sharing: one invite used from many networks or devices.
SELECT attendee_id, COUNT(DISTINCT ip_hash) AS ips, COUNT(DISTINCT ua) AS uas, COUNT(DISTINCT country) AS countries
FROM access_log
WHERE attendee_id IS NOT NULL
GROUP BY attendee_id
HAVING ips > 3 OR countries > 1
ORDER BY ips DESC;

-- 6. Progression: page views in order, with the gap since the previous one.
--    Steady readers show minute-scale gaps; bulk grabs show sub-second gaps.
SELECT attendee_id, datetime(ts / 1000, 'unixepoch') AS at, path,
       (ts - LAG(ts) OVER (PARTITION BY attendee_id ORDER BY ts)) / 1000 AS gap_s
FROM access_log
WHERE kind = 'page' AND status = 200
ORDER BY attendee_id, ts;
