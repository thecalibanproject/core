-- Replaces this request's pending record with its result, if the lease is still ours.
-- KEYS[1] record key; ARGV[1] our pending record; ARGV[2] done record; ARGV[3] TTL in ms.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
  return 1
end
return 0
