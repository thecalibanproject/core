-- Replaces a reservation made by reserve.lua with the amount actually used, atomically.
--
-- KEYS     as in reserve.lua
-- ARGV     reserved_tokens, reserved_usd, actual_tokens, actual_usd, reservation_day
--
-- Minute bucket: refill, then credit (reserved - actual); a refund is capped at the capacity,
-- an under-estimate leaves the bucket in debt so the next request waits.
-- Day counters: if the reservation was made today, swap it for the actual amount; if the day
-- rolled over while the request ran, charge the actual amount to the new day.
-- Same rules as InMemoryQuota::settle_at. Returns 1.
local function fmt(x) return string.format('%.17g', x) end

local t = redis.call('TIME')
local secs = tonumber(t[1])
local now = secs + tonumber(t[2]) / 1000000
local day = math.floor(secs / 86400)
local left = 86400 - (secs % 86400)

local reserved = tonumber(ARGV[1])
local reserved_usd = tonumber(ARGV[2])
local actual = tonumber(ARGV[3])
local actual_usd = tonumber(ARGV[4])
local rday = tonumber(ARGV[5])

local b = redis.call('HMGET', KEYS[1], 'level', 'ts', 'cap')
local cap = tonumber(b[3])
if cap and cap > 0 then
  local rate = cap / 60
  local level = math.min(tonumber(b[1]) + math.max(0, now - tonumber(b[2])) * rate, cap)
  level = math.min(level + reserved - actual, cap)
  redis.call('HSET', KEYS[1], 'level', fmt(level), 'ts', fmt(now))
  redis.call('PEXPIRE', KEYS[1], math.max(1, math.ceil((cap - level) / rate * 1000)))
end

local d = redis.call('HMGET', KEYS[2], 'day', 'tokens', 'usd')
local tokens_used, usd_used = 0, 0
if tonumber(d[1]) == day then
  tokens_used = tonumber(d[2]) or 0
  usd_used = tonumber(d[3]) or 0
end
if rday == day then
  tokens_used = math.max(0, tokens_used - reserved) + actual
  usd_used = math.max(0, usd_used - reserved_usd) + actual_usd
else
  tokens_used = tokens_used + actual
  usd_used = usd_used + actual_usd
end
redis.call('HSET', KEYS[2], 'day', day, 'tokens', fmt(tokens_used), 'usd', fmt(usd_used))
redis.call('EXPIRE', KEYS[2], left + 60)
return 1
