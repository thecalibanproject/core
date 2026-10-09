-- GCRA request-rate check for one or two limits (tenant, then API key), all or nothing.
--
-- KEYS[i]  hash {tat, rpm}: theoretical arrival time of limit i in microseconds of server time,
--          and the rate it was computed for (a changed rate starts fresh, like a hot reload of
--          the in-memory store)
-- ARGV[i]  requests per minute of limit i; the burst equals the per-minute rate
--
-- Emission interval T = 60 s / rpm. A request is admitted when its new TAT, max(TAT, now) + T,
-- is at most 60 s (burst * T) ahead of now. Nothing is written unless every limit admits, so a
-- request refused by its key limit does not use up tenant capacity.
--
-- Returns {0} when admitted, or {i, wait_us} for the first limit that refuses.
-- Each key expires when its TAT passes (at which point it is equivalent to an absent key).
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local window = 60000000
local next_tat = {}
for i = 1, #KEYS do
  local rpm = ARGV[i]
  local interval = window / tonumber(rpm)
  local s = redis.call('HMGET', KEYS[i], 'tat', 'rpm')
  local tat = now
  if s[2] == rpm then
    tat = tonumber(s[1]) or now
  end
  if tat < now then tat = now end
  local n = tat + interval
  local excess = n - now - window
  if excess > 0 then
    return {i, math.ceil(excess)}
  end
  next_tat[i] = n
end
for i = 1, #KEYS do
  redis.call('HSET', KEYS[i], 'tat', string.format('%.0f', next_tat[i]), 'rpm', ARGV[i])
  redis.call('PEXPIRE', KEYS[i], math.max(1, math.ceil((next_tat[i] - now) / 1000)))
end
return {0}
