-- Claims an idempotency key, or returns what holds it.
-- KEYS[1] record key; ARGV[1] pending record (JSON); ARGV[2] lease TTL in ms.
-- Returns the existing record, or nil after claiming the key.
local v = redis.call('GET', KEYS[1])
if v then
  return v
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return false
