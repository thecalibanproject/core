-- Frees the key for a retry (the request failed), if the lease is still ours.
-- KEYS[1] record key; ARGV[1] our pending record.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
