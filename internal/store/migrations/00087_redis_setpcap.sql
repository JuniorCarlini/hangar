-- +goose Up
-- The redis:8 entrypoint drops to the redis user with setpriv, which clears
-- the capability bounding set and so needs SETPCAP. Services created from the
-- Redis templates before this fix crash-loop with "apply bounding set:
-- Operation not permitted"; give them the capability the template now has.
UPDATE services
SET cap_add_json = '["CHOWN","DAC_OVERRIDE","FOWNER","SETGID","SETUID","SETPCAP"]'
WHERE template IN ('redis-cache', 'redis-queue')
  AND cap_add_json = '["CHOWN","DAC_OVERRIDE","FOWNER","SETGID","SETUID"]';

-- +goose Down
UPDATE services
SET cap_add_json = '["CHOWN","DAC_OVERRIDE","FOWNER","SETGID","SETUID"]'
WHERE template IN ('redis-cache', 'redis-queue')
  AND cap_add_json = '["CHOWN","DAC_OVERRIDE","FOWNER","SETGID","SETUID","SETPCAP"]';
