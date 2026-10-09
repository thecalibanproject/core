-- Checks a tenant's token and USD budgets and reserves an amount against them, atomically.
--
-- KEYS[1]  minute bucket, hash {level, ts, cap}: `cap` tokens refilling at cap/60 per second;
--          `level` may be negative (debt) after an under-estimated request was settled
-- KEYS[2]  day counters, hash {day, tokens, usd}; reset when `day` is not today (UTC)
-- ARGV     tokens, usd, tokens_per_minute, tokens_per_day, usd_per_day ('' = no limit)
--
-- Returns {'ok', day} (day = days since the epoch, server time) when reserved, or
-- {limit, wait_ms} with limit one of tokens_per_day, usd_per_day, tokens_per_minute.
-- Same rules as InMemoryQuota::reserve_at. Server time (TIME) is used so routers with skewed
-- clocks still agree on refill and on the UTC day.
local function fmt(x) return string.format('%.17g', x) end

local t = redis.call('TIME')
local secs = tonumber(t[1])
local now = secs + tonumber(t[2]) / 1000000
local day = math.floor(secs / 86400)
local left = 86400 - (secs % 86400)

local need = tonumber(ARGV[1])
local usd = tonumber(ARGV[2])
local tpm = tonumber(ARGV[3])
local tpd = tonumber(ARGV[4])
local usd_day = tonumber(ARGV[5])

local d = redis.call('HMGET', KEYS[2], 'day', 'tokens', 'usd')
local tokens_used, usd_used = 0, 0
if tonumber(d[1]) == day then
  tokens_used = tonumber(d[2]) or 0
  usd_used = tonumber(d[3]) or 0
end
if tpd and tokens_used + need > tpd then
  return {'tokens_per_day', left * 1000}
end
if usd_day and (usd_used >= usd_day or usd_used + usd > usd_day) then
  return {'usd_per_day', left * 1000}
end

if tpm then
  local b = redis.call('HMGET', KEYS[1], 'level', 'ts', 'cap')
  local level, ts = tpm, now
  if tonumber(b[3]) == tpm then
    level = tonumber(b[1])
    ts = tonumber(b[2])
  end
  local rate = tpm / 60
  level = math.min(level + math.max(0, now - ts) * rate, tpm)
  -- A request bigger than the whole bucket is admitted once the bucket is full (not starved).
  if level < need and level < tpm then
    local wait = (math.min(need, tpm) - level) / rate
    return {'tokens_per_minute', math.max(1, math.ceil(wait * 1000))}
  end
  level = level - need
  redis.call('HSET', KEYS[1], 'level', fmt(level), 'ts', fmt(now), 'cap', fmt(tpm))
  -- Expires once refilled: a full bucket is the same as an absent one.
  redis.call('PEXPIRE', KEYS[1], math.max(1, math.ceil((tpm - level) / rate * 1000)))
else
  redis.call('DEL', KEYS[1])
end

redis.call('HSET', KEYS[2], 'day', day, 'tokens', fmt(tokens_used + need), 'usd', fmt(usd_used + usd))
redis.call('EXPIRE', KEYS[2], left + 60)
return {'ok', day}
