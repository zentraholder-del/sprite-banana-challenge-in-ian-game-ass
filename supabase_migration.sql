-- ============================================================================

-- FULL SECURITY MIGRATION Ã¢â‚¬â€ deny-by-default RLS + RPC-only data layer

-- Run the WHOLE file in Supabase SQL Editor, top to bottom, in one go.

-- Safe to re-run (every statement is idempotent).

-- AFTER it succeeds: deploy the matching client code, then hard-refresh.

-- Until both are done, the site will show errors Ã¢â‚¬â€ that is expected.

-- ============================================================================



CREATE EXTENSION IF NOT EXISTS pgcrypto;



-- ----------------------------------------------------------------------------

-- STEP 0: make sure every column the RPCs touch actually exists

-- ----------------------------------------------------------------------------

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS device_fp TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS school TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS admin_request_status TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS plaintext_reveal TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS request_id BIGINT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS used_by TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS rank TEXT;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

ALTER TABLE key_requests ADD COLUMN IF NOT EXISTS school TEXT;

ALTER TABLE key_requests ADD COLUMN IF NOT EXISTS deny_reason TEXT;

ALTER TABLE key_requests ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ;

ALTER TABLE key_requests ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE key_requests ADD COLUMN IF NOT EXISTS device_fp TEXT;

ALTER TABLE announcements ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE announcements ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ NULL;

ALTER TABLE announcements ADD COLUMN IF NOT EXISTS reminded BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS username TEXT;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS status TEXT;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS vip_until TIMESTAMPTZ;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS gold_until TIMESTAMPTZ;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS sparkle_until TIMESTAMPTZ;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS dbl_until TIMESTAMPTZ;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS name_color TEXT;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS glow BOOLEAN;

ALTER TABLE user_cosmetics ADD COLUMN IF NOT EXISTS hide_online BOOLEAN;



CREATE TABLE IF NOT EXISTS announcement_alerts (

  announcement_id BIGINT NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,

  username TEXT NOT NULL,

  alerted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (announcement_id, username)

);

CREATE TABLE IF NOT EXISTS blacklist_devices (

  fp TEXT PRIMARY KEY,

  reason TEXT NOT NULL DEFAULT '',

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()

);

CREATE TABLE IF NOT EXISTS xp_balances (username TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0, lifetime INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS xp_daily (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, username TEXT NOT NULL, day DATE NOT NULL, amount INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS daily_playtime (username TEXT NOT NULL, day DATE NOT NULL, seconds INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (username, day));

CREATE TABLE IF NOT EXISTS chat_settings (id INTEGER PRIMARY KEY, slowmode_seconds INTEGER NOT NULL DEFAULT 0);

INSERT INTO chat_settings (id, slowmode_seconds) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS troll_settings (id INTEGER PRIMARY KEY, jumpscare_image TEXT);

INSERT INTO troll_settings (id, jumpscare_image) VALUES (1, NULL) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS rank_perms (rank TEXT PRIMARY KEY, perms JSONB NOT NULL DEFAULT '{}');

CREATE TABLE IF NOT EXISTS app_config (id INTEGER PRIMARY KEY, locked BOOLEAN NOT NULL DEFAULT false, lock_message TEXT NOT NULL DEFAULT '');

INSERT INTO app_config (id, locked, lock_message) VALUES (1, false, '') ON CONFLICT (id) DO NOTHING;



-- Best-effort uniqueness (duplicate-tolerant RPC logic does not depend on these).

DO $$ BEGIN CREATE UNIQUE INDEX IF NOT EXISTS uq_daily_games ON daily_games(username, game, day); EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'uq_daily_games skipped: %', SQLERRM; END $$;

DO $$ BEGIN CREATE UNIQUE INDEX IF NOT EXISTS uq_quest_claims ON quest_claims(username, quest_key, day); EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'uq_quest_claims skipped: %', SQLERRM; END $$;

DO $$ BEGIN CREATE UNIQUE INDEX IF NOT EXISTS uq_typing_user ON typing(username); EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'uq_typing_user skipped: %', SQLERRM; END $$;

DO $$ BEGIN CREATE UNIQUE INDEX IF NOT EXISTS uq_cosmetics_user ON user_cosmetics(username); EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'uq_cosmetics_user skipped: %', SQLERRM; END $$;

-- Staff audit trail: who did what to whom, when. Append-only (no UPDATE
-- or DELETE path anywhere) and auto-pruned after 90 days. Created BEFORE
-- the lockdown loop below so it gets the same deny-by-default RLS.
CREATE TABLE IF NOT EXISTS staff_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);



-- ----------------------------------------------------------------------------

-- STEP 1: deny-by-default RLS on EVERY app table.

-- Drops ALL existing policies regardless of name (anon_all, "anon all", Ã¢â‚¬Â¦).

-- Public SELECT only where the content is inherently public AND rendered

-- in-app (chat, announcements, leaderboards, online lists, config flags).

-- ----------------------------------------------------------------------------

DO $$

DECLARE

  t TEXT;

  pub TEXT[] := ARRAY[

    'messages', 'announcements', 'active_sessions',

    'xp_balances', 'xp_daily', 'daily_playtime', 'user_cosmetics',

    'chat_settings', 'app_config', 'troll_settings', 'rank_perms',

    'typing', 'daily_games', 'quest_claims', 'xp_purchases'

  ];

  tbls TEXT[] := ARRAY[

    'license_keys', 'messages', 'key_requests', 'blacklist', 'active_sessions',

    'direct_messages', 'troll_events', 'announcements', 'announcement_alerts',

    'app_config', 'blocks', 'chat_settings', 'daily_games', 'daily_playtime',

    'friends', 'game_bans', 'quest_claims', 'rank_perms', 'reports',

    'troll_settings', 'typing', 'user_cosmetics', 'warnings', 'xp_balances',

    'xp_daily', 'xp_purchases', 'mutes', 'blacklist_devices', 'key_reset_requests',
    'staff_audit', 'tournaments', 'tournament_entries', 'tournament_matches'

  ];

  pol RECORD;

BEGIN
  FOREACH t IN ARRAY tbls LOOP
    BEGIN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
      FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = t LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', pol.policyname, t);
      END LOOP;
      EXECUTE format('REVOKE ALL ON public.%I FROM anon, authenticated', t);
      IF t = ANY(pub) THEN
        EXECUTE format('CREATE POLICY "public read" ON public.%I FOR SELECT TO anon USING (true)', t);
        EXECUTE format('GRANT SELECT ON public.%I TO anon', t);
      END IF;
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'lockdown skipped for %: %', t, SQLERRM;
    END;
  END LOOP;
END $$;


-- ----------------------------------------------------------------------------

-- STEP 2: shared helpers (rank lookup + permission matrix, server-side)

-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION caller_rank_of(input_username TEXT, input_token TEXT)

RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$

DECLARE r TEXT;

BEGIN

  SELECT COALESCE(rank, CASE WHEN is_admin THEN 'admin' ELSE 'user' END) INTO r

  FROM license_keys

  WHERE used_by = input_username AND session_token::text = input_token AND is_active = true;

  RETURN r;

END; $$;



CREATE OR REPLACE FUNCTION has_perm(caller_rank TEXT, perm TEXT)

RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$

DECLARE v JSONB;

BEGIN

  IF caller_rank = 'owner' THEN RETURN TRUE; END IF;

  IF caller_rank IS NULL THEN RETURN FALSE; END IF;

  SELECT perms INTO v FROM rank_perms WHERE rank = caller_rank;

  IF v IS NOT NULL AND v ? perm THEN RETURN COALESCE((v->>perm)::boolean, FALSE); END IF;

  IF caller_rank = 'admin' THEN

    RETURN perm IN ('tab.dashboard','tab.requests','tab.adminreqs','tab.keys','tab.blacklist',

      'tab.messages','tab.users','tab.playerdms','tab.reports','tab.troll','tab.activity',

      'keys.create','keys.modify_user','requests.decide','adminreqs.decide','users.moderate_user',

      'announce.post','announce.delete','chat.delete','blacklist.manage','troll.fire',
      'tournaments.manage');

  ELSIF caller_rank = 'mod' THEN

    RETURN perm IN ('tab.dashboard','tab.blacklist','tab.messages','tab.users','tab.reports',

      'keys.modify_user','users.moderate_user','announce.post','chat.delete','blacklist.manage');

  END IF;

  RETURN FALSE;

END; $$;



CREATE OR REPLACE FUNCTION session_user_ok(input_username TEXT, input_token TEXT)

RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$

BEGIN

  RETURN EXISTS (

    SELECT 1 FROM license_keys

    WHERE used_by = input_username AND session_token::text = input_token AND is_active = true

  );

END; $$;

-- ----------------------------------------------------------------------------


-- ----------------------------------------------------------------------------
-- STEP 3: auth + session + key-request RPCs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION validate_key(input_key TEXT, input_username TEXT, input_fp TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r license_keys%ROWTYPE;
  crank TEXT;
  new_token UUID;
  lk_locked BOOLEAN := FALSE;
  lk_msg TEXT := '';
BEGIN
  -- input_fp feeds DEVICE BLACKLIST enforcement only (no session locking):
  -- blocked fingerprints are rejected here, and the fp is recorded for
  -- future block-device actions. Never used to decide who may log in.
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = input_username) THEN
    RETURN json_build_object('success', false, 'error', 'blacklisted');
  END IF;
  SELECT * INTO r FROM license_keys WHERE key = upper(trim(input_key)) FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'invalid');
  END IF;
  IF NOT r.is_active THEN
    RETURN json_build_object('success', false, 'error', 'deactivated');
  END IF;
  BEGIN
    SELECT locked, lock_message INTO lk_locked, lk_msg FROM app_config WHERE id = 1;
  EXCEPTION WHEN undefined_table THEN lk_locked := FALSE;
  END;
  crank := COALESCE(r.rank, CASE WHEN r.is_admin THEN 'admin' ELSE 'user' END);
  IF lk_locked AND crank <> 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'locked', 'lock_message', COALESCE(lk_msg, ''));
  END IF;
  IF r.used_by IS NOT NULL AND lower(r.used_by) <> lower(input_username) THEN
    RETURN json_build_object('success', false, 'error', 'wrong_user', 'bound', r.used_by);
  END IF;
  -- Device blacklist: rejected whether or not the fp matches anything
  -- recorded. Checked before the hard lock so the message is accurate.
  IF (input_fp IS NOT NULL AND input_fp <> '' AND EXISTS (
      SELECT 1 FROM blacklist_devices WHERE fp = input_fp))
     OR (r.device_fp IS NOT NULL AND EXISTS (
      SELECT 1 FROM blacklist_devices WHERE fp = r.device_fp)) THEN
    RETURN json_build_object('success', false, 'error', 'device_blocked');
  END IF;
  -- Pure hard lock: any live token blocks every new login, no stale
  -- exception. The ONLY way back in is Reset my key (or staff action),
  -- which nulls the token. (Device fingerprints play no part here.)
  IF r.session_token IS NOT NULL THEN
    RETURN json_build_object('success', false, 'error', 'in_use');
  END IF;
  new_token := gen_random_uuid();
  UPDATE license_keys
  SET session_token = new_token::text,
      used_by = COALESCE(r.used_by, input_username),
      activated_at = COALESCE(activated_at, NOW()),
      device_fp = COALESCE(NULLIF(input_fp, ''), device_fp)
  WHERE id = r.id;
  RETURN json_build_object('success', true, 'rank', crank, 'is_admin', r.is_admin,
    'session_token', new_token, 'used_by', COALESCE(r.used_by, input_username),
    'welcome_back', (r.session_token IS NOT NULL));
END; $$;

CREATE OR REPLACE FUNCTION verify_session(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE r license_keys%ROWTYPE;
BEGIN
  SELECT * INTO r FROM license_keys
  WHERE session_token::text = input_token
    AND (input_username = '' OR lower(used_by) = lower(input_username))
    AND is_active = true;
  IF NOT FOUND THEN
    RETURN json_build_object('valid', false);
  END IF;
  -- Blacklisted names and blocked devices fail validation too, so an
  -- existing session is booted within one poll cycle, not just at login.
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = r.used_by) THEN
    RETURN json_build_object('valid', false);
  END IF;
  IF r.device_fp IS NOT NULL AND EXISTS (
    SELECT 1 FROM blacklist_devices WHERE fp = r.device_fp) THEN
    RETURN json_build_object('valid', false);
  END IF;
  RETURN json_build_object('valid', true, 'used_by', r.used_by,
    'rank', COALESCE(r.rank, CASE WHEN r.is_admin THEN 'admin' ELSE 'user' END),
    'is_admin', r.is_admin);
END; $$;

-- Clean logout frees the key immediately so it can be used again without
-- Reset. The token is nulled only on match, so a stale/rotated token can
-- never kill someone else's live session. Presence row dropped too.
-- Called best-effort from the client (fail-open: redirect either way).
CREATE OR REPLACE FUNCTION logout_session(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE license_keys SET session_token = NULL
  WHERE session_token::text = input_token
    AND (input_username = '' OR lower(used_by) = lower(input_username));
  BEGIN
    DELETE FROM active_sessions WHERE lower(username) = lower(input_username);
  EXCEPTION WHEN undefined_table THEN NULL;
  END;
  RETURN json_build_object('success', true);
END; $$;

-- Old 3-arg version must go first: same name + different arity would
-- otherwise linger as a second overload and confuse PostgREST matching.
DROP FUNCTION IF EXISTS submit_key_request(TEXT, TEXT, TEXT);
CREATE OR REPLACE FUNCTION submit_key_request(input_name TEXT, input_reason TEXT,
  input_school TEXT, input_fp TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE prev key_requests%ROWTYPE;
BEGIN
  -- Blocked names and blocked devices are rejected outright.
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = input_name) THEN
    RETURN json_build_object('success', false, 'error', 'blacklisted');
  END IF;
  IF input_fp IS NOT NULL AND input_fp <> '' AND EXISTS (
    SELECT 1 FROM blacklist_devices WHERE fp = input_fp) THEN
    RETURN json_build_object('success', false, 'error', 'device_blocked');
  END IF;
  SELECT * INTO prev FROM key_requests WHERE name = input_name ORDER BY id DESC LIMIT 1;
  IF FOUND AND prev.status = 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'pending');
  END IF;
  IF FOUND AND prev.created_at IS NOT NULL AND prev.created_at > NOW() - INTERVAL '24 hours' THEN
    RETURN json_build_object('success', false, 'error', 'cooldown',
      'retry_after', EXTRACT(EPOCH FROM (prev.created_at + INTERVAL '24 hours' - NOW()))::BIGINT);
  END IF;
  INSERT INTO key_requests (name, reason, school, status, device_fp)
  VALUES (input_name, input_reason, NULLIF(input_school, ''), 'pending',
    NULLIF(input_fp, ''));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION check_request_status(input_name TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE req key_requests%ROWTYPE;
DECLARE krev TEXT;
BEGIN
  SELECT * INTO req FROM key_requests WHERE name = input_name ORDER BY id DESC LIMIT 1;
  IF NOT FOUND THEN
    RETURN json_build_object('found', false);
  END IF;
  IF req.status = 'approved' THEN
    SELECT plaintext_reveal INTO krev FROM license_keys WHERE request_id = req.id ORDER BY id DESC LIMIT 1;
    RETURN json_build_object('found', true, 'status', 'approved', 'key', krev);
  END IF;
  RETURN json_build_object('found', true, 'status', req.status);
END; $$;

CREATE OR REPLACE FUNCTION presence_upsert(input_username TEXT, input_token TEXT, input_game TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ok', false);
  END IF;
  IF EXISTS (SELECT 1 FROM active_sessions WHERE username = input_username) THEN
    UPDATE active_sessions SET current_game = input_game, last_seen = NOW() WHERE username = input_username;
  ELSE
    INSERT INTO active_sessions (username, current_game, last_seen) VALUES (input_username, input_game, NOW());
  END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION presence_touch(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ok', false);
  END IF;
  UPDATE active_sessions SET last_seen = NOW() WHERE username = input_username;
  RETURN json_build_object('ok', true);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 4: staff key + request RPCs (server-enforced permission matrix)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION req_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.requests') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((
    SELECT json_agg(t ORDER BY t.id DESC) FROM (
      SELECT id, name, reason, school, status, created_at, status_updated_at, deny_reason,
        (device_fp IS NOT NULL AND EXISTS (
          SELECT 1 FROM blacklist_devices WHERE fp = key_requests.device_fp)) AS fp_blocked
      FROM key_requests ORDER BY id DESC LIMIT 100
    ) t
  ), '[]'::json);
END; $$;

-- Block the device that filed a key request (fingerprint never leaves the DB).
CREATE OR REPLACE FUNCTION block_requester_device(caller_username TEXT, caller_token TEXT,
  request_id BIGINT, reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; f TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  SELECT device_fp INTO f FROM key_requests WHERE id = request_id;
  IF f IS NULL OR f = '' THEN
    RETURN json_build_object('success', false, 'error', 'no-device');
  END IF;
  INSERT INTO blacklist_devices (fp, reason)
  VALUES (f, left(COALESCE(reason, ''), 200))
  ON CONFLICT (fp) DO NOTHING;
  PERFORM audit_log(caller_username, 'block_device',
    COALESCE((SELECT name FROM key_requests WHERE id = request_id), 'request#' || request_id::text),
    left(COALESCE(reason, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION approve_key_request(caller_username TEXT, caller_token TEXT,
  request_id BIGINT, custom_key TEXT DEFAULT NULL, key_rank TEXT DEFAULT 'user')
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  crank TEXT;
  final_key TEXT;
  req key_requests%ROWTYPE;
  req_school TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'requests.decide') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF key_rank NOT IN ('user', 'mod', 'admin') THEN
    RETURN json_build_object('success', false, 'error', 'Bad rank');
  END IF;
  IF key_rank = 'owner' AND EXISTS (SELECT 1 FROM license_keys WHERE rank = 'owner') THEN
    RETURN json_build_object('success', false, 'error', 'Owner key already exists');
  END IF;
  SELECT * INTO req FROM key_requests WHERE id = request_id;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Request not found');
  END IF;
  req_school := req.school;
  -- Random 12-hex-char key from built-in md5 (no extension dependency).
  final_key := upper(trim(COALESCE(NULLIF(custom_key, ''),
    substring(md5(random()::text || clock_timestamp()::text || request_id::text), 1, 12))));
  IF NOT final_key ~ '^[A-Z0-9-]{4,64}$' THEN
    RETURN json_build_object('success', false, 'error', 'Bad key format');
  END IF;
  INSERT INTO license_keys (key, is_active, is_admin, rank, request_id, plaintext_reveal, school, used_by)
  VALUES (final_key, true, key_rank IN ('admin', 'owner'), key_rank, request_id, final_key, req_school, req.name);
  UPDATE key_requests SET status = 'approved', status_updated_at = NOW() WHERE id = request_id;
  PERFORM audit_log(caller_username, 'approve_key_request', req.name, final_key);
  RETURN json_build_object('success', true, 'key', final_key);
END; $$;

CREATE OR REPLACE FUNCTION deny_key_request(caller_username TEXT, caller_token TEXT,
  request_id BIGINT, input_reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'requests.decide') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  UPDATE key_requests SET status = 'denied', status_updated_at = NOW(),
    deny_reason = left(COALESCE(input_reason, ''), 200)
  WHERE id = request_id;
  PERFORM audit_log(caller_username, 'deny_key_request',
    COALESCE((SELECT name FROM key_requests WHERE id = request_id), 'request#' || request_id::text),
    left(COALESCE(input_reason, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE TABLE IF NOT EXISTS key_reset_requests (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL,
  key_value TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  device_fp TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  deny_reason TEXT NOT NULL DEFAULT '',
  decided_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status_updated_at TIMESTAMPTZ
);

-- Reset requests: the ONLY path to freeing a locked key. Instant
-- self-service reset was removed on purpose: anyone holding a leaked
-- name+key could steal the live session with it. Staff approve/deny here,
-- same audience as key requests. Cooldown only after a denial; an approved
-- user who gets locked again may ask again immediately.
CREATE OR REPLACE FUNCTION submit_reset_request(input_name TEXT, input_key TEXT,
  input_reason TEXT DEFAULT '', input_fp TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE k license_keys%ROWTYPE; prev key_reset_requests%ROWTYPE;
BEGIN
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = input_name) THEN
    RETURN json_build_object('success', false, 'error', 'blacklisted');
  END IF;
  IF input_fp IS NOT NULL AND input_fp <> '' AND EXISTS (
    SELECT 1 FROM blacklist_devices WHERE fp = input_fp) THEN
    RETURN json_build_object('success', false, 'error', 'device_blocked');
  END IF;
  SELECT * INTO k FROM license_keys WHERE key = upper(trim(input_key));
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'invalid');
  END IF;
  IF NOT k.is_active THEN
    RETURN json_build_object('success', false, 'error', 'deactivated');
  END IF;
  IF k.used_by IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'unbound');
  END IF;
  IF lower(k.used_by) <> lower(input_name) THEN
    RETURN json_build_object('success', false, 'error', 'wrong_user');
  END IF;
  IF k.session_token IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'no-session');
  END IF;
  SELECT * INTO prev FROM key_reset_requests
  WHERE upper(key_value) = upper(trim(input_key)) ORDER BY id DESC LIMIT 1;
  IF FOUND AND prev.status = 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'pending');
  END IF;
  IF FOUND AND prev.status = 'denied' AND prev.status_updated_at IS NOT NULL
     AND prev.status_updated_at > NOW() - INTERVAL '24 hours' THEN
    RETURN json_build_object('success', false, 'error', 'cooldown',
      'retry_after', EXTRACT(EPOCH FROM (prev.status_updated_at + INTERVAL '24 hours' - NOW()))::BIGINT);
  END IF;
  INSERT INTO key_reset_requests (name, key_value, reason, device_fp, status)
  VALUES (input_name, upper(trim(input_key)), left(COALESCE(input_reason, ''), 200),
    NULLIF(input_fp, ''), 'pending');
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION check_reset_status(input_name TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE req key_reset_requests%ROWTYPE;
BEGIN
  SELECT * INTO req FROM key_reset_requests WHERE name = input_name ORDER BY id DESC LIMIT 1;
  IF NOT FOUND THEN
    RETURN json_build_object('found', false);
  END IF;
  RETURN json_build_object('found', true, 'status', req.status,
    'deny_reason', COALESCE(req.deny_reason, ''));
END; $$;

CREATE OR REPLACE FUNCTION resetreq_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.requests') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((
    SELECT json_agg(t ORDER BY t.id DESC) FROM (
      SELECT id, name, key_value, reason, status, created_at, status_updated_at,
        deny_reason, decided_by,
        (SELECT (session_token IS NOT NULL) FROM license_keys
         WHERE key = key_reset_requests.key_value) AS live_session,
        (device_fp IS NOT NULL AND EXISTS (
          SELECT 1 FROM blacklist_devices WHERE fp = key_reset_requests.device_fp)) AS fp_blocked
      FROM key_reset_requests ORDER BY id DESC LIMIT 100
    ) t
  ), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION resetreq_approve(caller_username TEXT, caller_token TEXT,
  request_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; req key_reset_requests%ROWTYPE; k license_keys%ROWTYPE;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'requests.decide') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  SELECT * INTO req FROM key_reset_requests WHERE id = request_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Request not found');
  END IF;
  IF req.status <> 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'Already decided');
  END IF;
  SELECT * INTO k FROM license_keys WHERE key = req.key_value;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Key gone');
  END IF;
  IF k.used_by IS NULL OR lower(k.used_by) <> lower(req.name) THEN
    RETURN json_build_object('success', false, 'error', 'Name mismatch');
  END IF;
  UPDATE license_keys SET session_token = NULL, activated_at = NULL WHERE id = k.id;
  UPDATE key_reset_requests SET status = 'approved', status_updated_at = NOW(),
    decided_by = caller_username WHERE id = request_id;
  PERFORM audit_log(caller_username, 'resetreq_approve', req.name, req.key_value);
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION resetreq_deny(caller_username TEXT, caller_token TEXT,
  request_id BIGINT, input_reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'requests.decide') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  UPDATE key_reset_requests SET status = 'denied', status_updated_at = NOW(),
    deny_reason = left(COALESCE(input_reason, ''), 200),
    decided_by = caller_username
  WHERE id = request_id;
  PERFORM audit_log(caller_username, 'resetreq_deny',
    COALESCE((SELECT name FROM key_reset_requests WHERE id = request_id), 'request#' || request_id::text),
    left(COALESCE(input_reason, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE TABLE IF NOT EXISTS tournaments (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title TEXT NOT NULL,
  game_slug TEXT NOT NULL DEFAULT 'penkick',
  status TEXT NOT NULL DEFAULT 'signup',
  max_players INT NOT NULL DEFAULT 16,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tournament_entries (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tournament_id BIGINT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tournament_id, username)
);

CREATE TABLE IF NOT EXISTS tournament_matches (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tournament_id BIGINT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
  round_no INT NOT NULL DEFAULT 1,
  match_no INT NOT NULL DEFAULT 1,
  player_a TEXT,
  player_b TEXT,
  score_a INT,
  score_b INT,
  winner TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tournament_id, round_no, match_no)
);

-- Tournaments: staff-run single-elimination cups. Players join during
-- signup; staff starts (shuffled bracket, odd player out gets a bye);
-- staff decides each tie by score (ties need an explicit winner pick) and
-- the next round builds itself as rounds complete. Bracket view for all.
CREATE OR REPLACE FUNCTION tourney_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('error', 'auth');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT t.id, t.title, t.game_slug, t.status, t.max_players, t.created_by, t.created_at,
      (SELECT COUNT(*) FROM tournament_entries e WHERE e.tournament_id = t.id) AS entries,
      EXISTS (SELECT 1 FROM tournament_entries e
        WHERE e.tournament_id = t.id AND lower(e.username) = lower(input_username)) AS mine,
      (SELECT m.winner FROM tournament_matches m
        WHERE m.tournament_id = t.id AND m.winner IS NOT NULL
        ORDER BY m.round_no DESC, m.match_no DESC LIMIT 1) AS last_winner
    FROM tournaments t WHERE t.status <> 'cancelled' ORDER BY t.id DESC LIMIT 20
  ) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION tourney_detail(input_username TEXT, input_token TEXT, tid BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE tro tournaments%ROWTYPE;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('error', 'auth');
  END IF;
  SELECT * INTO tro FROM tournaments WHERE id = tid;
  IF NOT FOUND THEN
    RETURN json_build_object('error', 'not found');
  END IF;
  RETURN json_build_object(
    'tournament', row_to_json(tro),
    'entries', COALESCE((SELECT json_agg(e ORDER BY e.id) FROM (
      SELECT id, username, created_at FROM tournament_entries
      WHERE tournament_id = tid ORDER BY id) e), '[]'::json),
    'matches', COALESCE((SELECT json_agg(m ORDER BY m.round_no, m.match_no) FROM (
      SELECT id, round_no, match_no, player_a, player_b, score_a, score_b,
        winner, status FROM tournament_matches
      WHERE tournament_id = tid ORDER BY round_no, match_no) m), '[]'::json));
END; $$;

CREATE OR REPLACE FUNCTION tourney_create(caller_username TEXT, caller_token TEXT,
  title TEXT, game_slug TEXT DEFAULT 'penkick', max_players INT DEFAULT 16)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; nid BIGINT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tournaments.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF title IS NULL OR length(trim(title)) < 3 OR length(title) > 80 THEN
    RETURN json_build_object('success', false, 'error', 'Title must be 3-80 chars');
  END IF;
  max_players := GREATEST(2, LEAST(COALESCE(max_players, 16), 64));
  INSERT INTO tournaments (title, game_slug, status, max_players, created_by)
  VALUES (trim(title), left(COALESCE(NULLIF(trim(game_slug), ''), 'penkick'), 64),
    'signup', max_players, caller_username)
  RETURNING id INTO nid;
  PERFORM audit_log(caller_username, 'tourney_create', trim(title), 'max=' || max_players::text);
  RETURN json_build_object('success', true, 'id', nid);
END; $$;

CREATE OR REPLACE FUNCTION tourney_join(input_username TEXT, input_token TEXT, tid BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE tro tournaments%ROWTYPE; cnt INT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF EXISTS (SELECT 1 FROM blacklist WHERE lower(username) = lower(input_username)) THEN
    RETURN json_build_object('success', false, 'error', 'blacklisted');
  END IF;
  SELECT * INTO tro FROM tournaments WHERE id = tid;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF tro.status <> 'signup' THEN
    RETURN json_build_object('success', false, 'error', 'Signups are closed');
  END IF;
  SELECT COUNT(*) INTO cnt FROM tournament_entries WHERE tournament_id = tid;
  IF cnt >= tro.max_players THEN
    RETURN json_build_object('success', false, 'error', 'Tournament is full');
  END IF;
  BEGIN
    INSERT INTO tournament_entries (tournament_id, username) VALUES (tid, input_username);
  EXCEPTION WHEN unique_violation THEN
    RETURN json_build_object('success', false, 'error', 'Already joined');
  END;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION tourney_start(caller_username TEXT, caller_token TEXT, tid BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; tro tournaments%ROWTYPE; names TEXT[]; n INT; i INT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tournaments.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  SELECT * INTO tro FROM tournaments WHERE id = tid FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF tro.status <> 'signup' THEN
    RETURN json_build_object('success', false, 'error', 'Already started');
  END IF;
  SELECT COALESCE(array_agg(username ORDER BY random()), '{}') INTO names
  FROM tournament_entries WHERE tournament_id = tid;
  n := COALESCE(array_length(names, 1), 0);
  IF n < 2 THEN
    RETURN json_build_object('success', false, 'error', 'Need at least 2 players');
  END IF;
  UPDATE tournaments SET status = 'live' WHERE id = tid;
  i := 1;
  WHILE i <= n LOOP
    IF i = n THEN
      INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, winner, status)
      VALUES (tid, 1, (i + 1) / 2, names[i], names[i], 'bye');
    ELSE
      INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, player_b)
      VALUES (tid, 1, (i + 1) / 2, names[i], names[i + 1]);
    END IF;
    i := i + 2;
  END LOOP;
  PERFORM audit_log(caller_username, 'tourney_start', tro.title, n::text || ' players');
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION tourney_decide(caller_username TEXT, caller_token TEXT,
  match_id BIGINT, score_a INT, score_b INT, winner_override TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; m tournament_matches%ROWTYPE; tstat TEXT;
DECLARE w TEXT; pend INT; wins TEXT[]; i INT; r INT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tournaments.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  SELECT * INTO m FROM tournament_matches WHERE id = match_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Match not found');
  END IF;
  IF m.status <> 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'Already decided');
  END IF;
  SELECT status INTO tstat FROM tournaments WHERE id = m.tournament_id;
  IF tstat <> 'live' THEN
    RETURN json_build_object('success', false, 'error', 'Tournament is not live');
  END IF;
  IF score_a IS NULL OR score_b IS NULL OR score_a < 0 OR score_b < 0
     OR score_a > 999 OR score_b > 999 THEN
    RETURN json_build_object('success', false, 'error', 'Bad scores');
  END IF;
  IF winner_override IS NOT NULL AND winner_override <> '' THEN
    IF lower(winner_override) = lower(COALESCE(m.player_a, '')) THEN w := m.player_a;
    ELSIF lower(winner_override) = lower(COALESCE(m.player_b, '')) THEN w := m.player_b;
    ELSE RETURN json_build_object('success', false, 'error', 'Winner must be a player in this tie');
    END IF;
  ELSIF score_a > score_b THEN w := m.player_a;
  ELSIF score_b > score_a THEN w := m.player_b;
  ELSE RETURN json_build_object('success', false, 'error', 'Tie: pick a winner');
  END IF;
  IF w IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'No winner available');
  END IF;
  UPDATE tournament_matches
  SET score_a = tourney_decide.score_a, score_b = tourney_decide.score_b, winner = w, status = 'decided'
  WHERE id = match_id;
  -- Auto-advance: when the round is complete, build the next round from
  -- its winners (odd one out gets a bye); a lone winner takes the cup.
  SELECT COUNT(*) INTO pend FROM tournament_matches
  WHERE tournament_id = m.tournament_id AND round_no = m.round_no AND status = 'pending';
  IF pend = 0 THEN
    SELECT COALESCE(array_agg(winner ORDER BY match_no), '{}') INTO wins
    FROM tournament_matches
    WHERE tournament_id = m.tournament_id AND round_no = m.round_no AND winner IS NOT NULL;
    IF COALESCE(array_length(wins, 1), 0) = 1 THEN
      UPDATE tournaments SET status = 'finished' WHERE id = m.tournament_id;
    ELSIF NOT EXISTS (SELECT 1 FROM tournament_matches
           WHERE tournament_id = m.tournament_id AND round_no = m.round_no + 1) THEN
      r := m.round_no + 1;
      i := 1;
      WHILE i <= array_length(wins, 1) LOOP
        IF i = array_length(wins, 1) THEN
          INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, winner, status)
          VALUES (m.tournament_id, r, (i + 1) / 2, wins[i], wins[i], 'bye');
        ELSE
          INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, player_b)
          VALUES (m.tournament_id, r, (i + 1) / 2, wins[i], wins[i + 1]);
        END IF;
        i := i + 2;
      END LOOP;
    END IF;
  END IF;
  PERFORM audit_log(caller_username, 'tourney_decide',
    (SELECT title FROM tournaments WHERE id = m.tournament_id),
    COALESCE(m.player_a, '?') || ' ' || tourney_decide.score_a::text || '-' || tourney_decide.score_b::text || ' ' || COALESCE(m.player_b, '?'));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION tourney_cancel(caller_username TEXT, caller_token TEXT, tid BIGINT)RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tournaments.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  UPDATE tournaments SET status = 'cancelled' WHERE id = tid AND status IN ('signup', 'live');
  PERFORM audit_log(caller_username, 'tourney_cancel',
    COALESCE((SELECT title FROM tournaments WHERE id = tid), 'id#' || tid::text), '');
  RETURN json_build_object('success', true);
END; $$;

-- Staff adds a player directly (school cups: teacher drafts kids, nobody
-- has to join). Target must hold an active key.
CREATE OR REPLACE FUNCTION tourney_add(caller_username TEXT, caller_token TEXT,
  tid BIGINT, target_username TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; tro tournaments%ROWTYPE; cnt INT; canon TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tournaments.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF target_username IS NULL OR trim(target_username) = '' THEN
    RETURN json_build_object('success', false, 'error', 'Bad username');
  END IF;
  SELECT * INTO tro FROM tournaments WHERE id = tid;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF tro.status <> 'signup' THEN
    RETURN json_build_object('success', false, 'error', 'Signups are closed');
  END IF;
  SELECT used_by INTO canon FROM license_keys
  WHERE lower(used_by) = lower(trim(target_username)) AND is_active = true
  ORDER BY id LIMIT 1;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'No active key for that name');
  END IF;
  SELECT COUNT(*) INTO cnt FROM tournament_entries WHERE tournament_id = tid;
  IF cnt >= tro.max_players THEN
    RETURN json_build_object('success', false, 'error', 'Tournament is full');
  END IF;
  BEGIN
    INSERT INTO tournament_entries (tournament_id, username) VALUES (tid, canon);
  EXCEPTION WHEN unique_violation THEN
    RETURN json_build_object('success', false, 'error', 'Already joined');
  END;
  PERFORM audit_log(caller_username, 'tourney_add',
    COALESCE((SELECT title FROM tournaments WHERE id = tid), ''), canon);
  RETURN json_build_object('success', true);
END; $$;

-- "Is it my turn?": my earliest live pending tie where my current-round
-- pick is still missing. Powers the auto-drag: the hub polls this and
-- yanks the player straight into their tie.
CREATE OR REPLACE FUNCTION tourney_myturn(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE mid BIGINT; tid BIGINT; ttl TEXT; r INT;
DECLARE shooter TEXT; keeper TEXT; prow shootout_picks%ROWTYPE;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('error', 'auth');
  END IF;
  SELECT m.id, m.tournament_id INTO mid, tid FROM tournament_matches m
  JOIN tournaments t ON t.id = m.tournament_id
  WHERE m.status = 'pending' AND t.status = 'live'
    AND (lower(m.player_a) = lower(input_username) OR lower(m.player_b) = lower(input_username))
    AND ((lower(m.player_a) = lower(input_username) AND m.sub_a IS NULL)
      OR (lower(m.player_b) = lower(input_username) AND m.sub_b IS NULL))
  ORDER BY m.id LIMIT 1;
  IF NOT FOUND THEN
    RETURN json_build_object('turn', false);
  END IF;
  SELECT COALESCE(MAX(round_no), 0) INTO r FROM shootout_picks
  WHERE shootout_picks.match_id = tourney_myturn.mid;
  IF r = 0 THEN r := 1; END IF;
  SELECT * INTO prow FROM shootout_picks
  WHERE shootout_picks.match_id = tourney_myturn.mid
    AND shootout_picks.round_no = r;
  IF FOUND AND prow.shoot_zone IS NOT NULL AND prow.keep_zone IS NOT NULL THEN
    r := r + 1;
    SELECT * INTO prow FROM shootout_picks
    WHERE shootout_picks.match_id = tourney_myturn.mid
      AND shootout_picks.round_no = r;
  END IF;
  IF FOUND THEN
    IF prow.shooter IS NOT NULL AND lower(prow.shooter) = lower(input_username)
       AND prow.shoot_zone IS NOT NULL THEN
      RETURN json_build_object('turn', false);
    END IF;
    IF prow.keeper IS NOT NULL AND lower(prow.keeper) = lower(input_username)
       AND prow.keep_zone IS NOT NULL THEN
      RETURN json_build_object('turn', false);
    END IF;
    shooter := prow.shooter; keeper := prow.keeper;
  ELSE
    SELECT player_a, player_b INTO shooter, keeper FROM tournament_matches WHERE id = mid;
    IF r % 2 = 0 THEN
      DECLARE tmp TEXT; BEGIN tmp := shooter; shooter := keeper; keeper := tmp; END;
    END IF;
  END IF;
  SELECT title INTO ttl FROM tournaments WHERE id = tid;
  RETURN json_build_object('turn', true, 'tournament_id', tid,
    'match_id', mid, 'round_no', r, 'title', COALESCE(ttl, ''),
    'i_shoot', (lower(input_username) = lower(COALESCE(shooter, ''))));
END; $$;

ALTER TABLE tournament_matches ADD COLUMN IF NOT EXISTS sub_a INT;
ALTER TABLE tournament_matches ADD COLUMN IF NOT EXISTS sub_b INT;

CREATE TABLE IF NOT EXISTS shootout_picks (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  match_id BIGINT NOT NULL REFERENCES tournament_matches(id) ON DELETE CASCADE,
  round_no INT NOT NULL DEFAULT 1,
  shooter TEXT NOT NULL,
  keeper TEXT NOT NULL,
  shoot_zone INT,
  keep_zone INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(match_id, round_no)
);

-- Async shootout picks: the kick resolves only once BOTH zones are stored,
-- so a live keeper reads a live shooter every round with zero syncing.
-- Odd rounds: player_a shoots; even rounds: player_b shoots. Zone match =
-- saved, anything else = goal. Fully deterministic: both clients animate
-- the identical outcome from the same two numbers.
CREATE OR REPLACE FUNCTION shootout_pick(input_username TEXT, input_token TEXT,
  match_id BIGINT, round_no INT, zone INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE m tournament_matches%ROWTYPE; tstat TEXT;
DECLARE shooter TEXT; keeper TEXT; r shootout_picks%ROWTYPE;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF zone IS NULL OR zone < 1 OR zone > 6 THEN
    RETURN json_build_object('success', false, 'error', 'Bad zone');
  END IF;
  IF round_no IS NULL OR round_no < 1 OR round_no > 99 THEN
    RETURN json_build_object('success', false, 'error', 'Bad round');
  END IF;
  SELECT * INTO m FROM tournament_matches WHERE id = match_id;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Match not found');
  END IF;
  IF m.status <> 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'Match is over');
  END IF;
  SELECT status INTO tstat FROM tournaments WHERE id = m.tournament_id;
  IF tstat <> 'live' THEN
    RETURN json_build_object('success', false, 'error', 'Tournament is not live');
  END IF;
  IF m.player_a IS NULL OR m.player_b IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'No opponent yet');
  END IF;
  IF round_no % 2 = 1 THEN shooter := m.player_a; keeper := m.player_b;
  ELSE shooter := m.player_b; keeper := m.player_a; END IF;
  IF lower(input_username) <> lower(shooter) AND lower(input_username) <> lower(keeper) THEN
    RETURN json_build_object('success', false, 'error', 'Not your tie');
  END IF;
  SELECT * INTO r FROM shootout_picks
  WHERE shootout_picks.match_id = shootout_pick.match_id
    AND shootout_picks.round_no = shootout_pick.round_no;
  IF NOT FOUND THEN
    INSERT INTO shootout_picks (match_id, round_no, shooter, keeper)
    VALUES (shootout_pick.match_id, shootout_pick.round_no,
      shootout_pick.shooter, shootout_pick.keeper)
    ON CONFLICT (match_id, round_no) DO NOTHING;
    SELECT * INTO r FROM shootout_picks
    WHERE shootout_picks.match_id = shootout_pick.match_id
      AND shootout_picks.round_no = shootout_pick.round_no;
  END IF;
  IF lower(input_username) = lower(r.shooter) THEN
    IF r.shoot_zone IS NOT NULL THEN
      RETURN json_build_object('success', false, 'error', 'Already picked');
    END IF;
    UPDATE shootout_picks SET shoot_zone = zone
    WHERE shootout_picks.match_id = shootout_pick.match_id
      AND shootout_picks.round_no = shootout_pick.round_no;
  ELSIF lower(input_username) = lower(r.keeper) THEN
    IF r.keep_zone IS NOT NULL THEN
      RETURN json_build_object('success', false, 'error', 'Already picked');
    END IF;
    UPDATE shootout_picks SET keep_zone = zone
    WHERE shootout_picks.match_id = shootout_pick.match_id
      AND shootout_picks.round_no = shootout_pick.round_no;
  ELSE
    RETURN json_build_object('success', false, 'error', 'Not your tie');
  END IF;
  SELECT * INTO r FROM shootout_picks
  WHERE shootout_picks.match_id = shootout_pick.match_id
    AND shootout_picks.round_no = shootout_pick.round_no;
  RETURN json_build_object('success', true,
    'resolved', (r.shoot_zone IS NOT NULL AND r.keep_zone IS NOT NULL));
END; $$;

CREATE OR REPLACE FUNCTION shootout_state(input_username TEXT, input_token TEXT,
  match_id BIGINT, round_no INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE m tournament_matches%ROWTYPE; r shootout_picks%ROWTYPE;
DECLARE shooter TEXT; keeper TEXT; resolved BOOLEAN := FALSE; tstat TEXT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('error', 'auth');
  END IF;
  SELECT * INTO m FROM tournament_matches WHERE id = match_id;
  IF NOT FOUND THEN
    RETURN json_build_object('error', 'not found');
  END IF;
  SELECT status INTO tstat FROM tournaments WHERE id = m.tournament_id;
  IF round_no % 2 = 1 THEN shooter := m.player_a; keeper := m.player_b;
  ELSE shooter := m.player_b; keeper := m.player_a; END IF;
  SELECT * INTO r FROM shootout_picks
  WHERE shootout_picks.match_id = shootout_state.match_id
    AND shootout_picks.round_no = shootout_state.round_no;
  IF FOUND AND r.shoot_zone IS NOT NULL AND r.keep_zone IS NOT NULL THEN
    resolved := TRUE;
  END IF;
  RETURN json_build_object(
    'found', FOUND,
    'match_status', m.status,
    'tournament_status', tstat,
    'player_a', m.player_a, 'player_b', m.player_b,
    'winner', m.winner,
    'shooter', shooter, 'keeper', keeper,
    'i_shoot', (lower(input_username) = lower(COALESCE(shooter, ''))),
    'my_pick', CASE WHEN lower(input_username) = lower(COALESCE(shooter, '')) THEN r.shoot_zone
                   WHEN lower(input_username) = lower(COALESCE(keeper, '')) THEN r.keep_zone END,
    'shoot_zone', CASE WHEN resolved THEN r.shoot_zone END,
    'keep_zone', CASE WHEN resolved THEN r.keep_zone END,
    'resolved', resolved);
END; $$;

-- Player score submit: each side posts their own final goals. When both
-- are in and agree, the tie decides itself (same advance rules as staff).
CREATE OR REPLACE FUNCTION tourney_submit(input_username TEXT, input_token TEXT,
  match_id BIGINT, goals INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE m tournament_matches%ROWTYPE; tstat TEXT;
DECLARE sa INT; sb INT; w TEXT; pend INT; wins TEXT[]; i INT; r INT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF goals IS NULL OR goals < 0 OR goals > 99 THEN
    RETURN json_build_object('success', false, 'error', 'Bad score');
  END IF;
  SELECT * INTO m FROM tournament_matches WHERE id = match_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'error', 'Match not found');
  END IF;
  IF m.status <> 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'Match is over');
  END IF;
  SELECT status INTO tstat FROM tournaments WHERE id = m.tournament_id;
  IF tstat <> 'live' THEN
    RETURN json_build_object('success', false, 'error', 'Tournament is not live');
  END IF;
  IF lower(input_username) = lower(COALESCE(m.player_a, '')) THEN
    UPDATE tournament_matches SET sub_a = goals WHERE id = match_id;
  ELSIF lower(input_username) = lower(COALESCE(m.player_b, '')) THEN
    UPDATE tournament_matches SET sub_b = goals WHERE id = match_id;
  ELSE
    RETURN json_build_object('success', false, 'error', 'Not your tie');
  END IF;
  SELECT sub_a, sub_b INTO sa, sb FROM tournament_matches WHERE id = match_id;
  IF sa IS NULL OR sb IS NULL THEN
    RETURN json_build_object('success', true, 'decided', false);
  END IF;
  IF sa = sb THEN
    RETURN json_build_object('success', false, 'error', 'Tie: keep playing sudden death');
  END IF;
  IF sa > sb THEN w := m.player_a; ELSE w := m.player_b; END IF;
  UPDATE tournament_matches
  SET score_a = sa, score_b = sb, winner = w, status = 'decided'
  WHERE id = match_id;
  SELECT COUNT(*) INTO pend FROM tournament_matches
  WHERE tournament_id = m.tournament_id AND round_no = m.round_no AND status = 'pending';
  IF pend = 0 THEN
    SELECT COALESCE(array_agg(winner ORDER BY match_no), '{}') INTO wins
    FROM tournament_matches
    WHERE tournament_id = m.tournament_id AND round_no = m.round_no AND winner IS NOT NULL;
    IF COALESCE(array_length(wins, 1), 0) = 1 THEN
      UPDATE tournaments SET status = 'finished' WHERE id = m.tournament_id;
    ELSIF NOT EXISTS (SELECT 1 FROM tournament_matches
           WHERE tournament_id = m.tournament_id AND round_no = m.round_no + 1) THEN
      r := m.round_no + 1;
      i := 1;
      WHILE i <= array_length(wins, 1) LOOP
        IF i = array_length(wins, 1) THEN
          INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, winner, status)
          VALUES (m.tournament_id, r, (i + 1) / 2, wins[i], wins[i], 'bye');
        ELSE
          INSERT INTO tournament_matches (tournament_id, round_no, match_no, player_a, player_b)
          VALUES (m.tournament_id, r, (i + 1) / 2, wins[i], wins[i + 1]);
        END IF;
        i := i + 2;
      END LOOP;
    END IF;
  END IF;
  PERFORM audit_log(input_username, 'tourney_submit',
    COALESCE((SELECT title FROM tournaments WHERE id = m.tournament_id), ''),
    COALESCE(m.player_a, '?') || ' ' || sa::text || '-' || sb::text || ' ' || COALESCE(m.player_b, '?'));
  RETURN json_build_object('success', true, 'decided', true, 'winner', w);
END; $$;

CREATE OR REPLACE FUNCTION adminreq_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.adminreqs') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN json_build_object(
    'pending', COALESCE((SELECT json_agg(t ORDER BY t.id) FROM (
      SELECT id, key, used_by, rank, admin_request_status, activated_at
      FROM license_keys WHERE admin_request_status = 'pending' ORDER BY id LIMIT 100) t), '[]'::json),
    'decided', COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
      SELECT id, used_by, admin_request_status
      FROM license_keys WHERE admin_request_status IN ('approved', 'denied')
      ORDER BY id DESC LIMIT 10) t), '[]'::json));
END; $$;

CREATE OR REPLACE FUNCTION adminreq_decide(caller_username TEXT, caller_token TEXT,
  target_key_id BIGINT, approve BOOLEAN)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'adminreqs.decide') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  PERFORM audit_log(caller_username, CASE WHEN approve THEN 'adminreq_approve' ELSE 'adminreq_deny' END,
    COALESCE((SELECT used_by FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
  IF approve THEN
    UPDATE license_keys SET rank = 'admin', is_admin = true, admin_request_status = 'approved'
    WHERE id = target_key_id;
  ELSE
    UPDATE license_keys SET admin_request_status = 'denied' WHERE id = target_key_id;
  END IF;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION keys_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.keys') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((
    SELECT json_agg(t ORDER BY t.id DESC) FROM (
      SELECT id, key, used_by, rank, is_active, created_at, school,
        admin_request_status, plaintext_reveal, request_id
      FROM license_keys ORDER BY id DESC LIMIT 200
    ) t
  ), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION key_create_bulk(caller_username TEXT, caller_token TEXT,
  input_keys TEXT[], key_rank TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  crank TEXT;
  k TEXT;
  n INT := 0;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'keys.create') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF key_rank NOT IN ('user', 'mod', 'admin', 'owner') THEN
    RETURN json_build_object('success', false, 'error', 'Bad rank');
  END IF;
  IF key_rank = 'owner' THEN
    IF crank <> 'owner' THEN
      RETURN json_build_object('success', false, 'error', 'Insufficient rank');
    END IF;
    IF EXISTS (SELECT 1 FROM license_keys WHERE rank = 'owner') THEN
      RETURN json_build_object('success', false, 'error', 'Owner key already exists');
    END IF;
  END IF;
  FOREACH k IN ARRAY input_keys LOOP
    k := upper(trim(k));
    IF k ~ '^[A-Z0-9-]{4,64}$' THEN
      BEGIN
        INSERT INTO license_keys (key, is_active, is_admin, rank, plaintext_reveal)
        VALUES (k, true, key_rank IN ('admin', 'owner'), key_rank, k);
        n := n + 1;
      EXCEPTION WHEN unique_violation THEN NULL;
      END;
    END IF;
  END LOOP;
  PERFORM audit_log(caller_username, 'keys_create', n::text || ' keys', 'rank=' || key_rank);
  RETURN json_build_object('success', true, 'created', n);
END; $$;

CREATE OR REPLACE FUNCTION toggle_key(caller_username TEXT, caller_token TEXT,
  target_key_id BIGINT, next_active BOOLEAN)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; trank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  SELECT COALESCE(rank, 'user') INTO trank FROM license_keys WHERE id = target_key_id;
  IF trank IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF crank = 'owner' THEN
    UPDATE license_keys SET is_active = next_active WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'toggle_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text),
      'active=' || next_active::text);
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    UPDATE license_keys SET is_active = next_active WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'toggle_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text),
      'active=' || next_active::text);
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
    UPDATE license_keys SET is_active = next_active WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'toggle_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text),
      'active=' || next_active::text);
    RETURN json_build_object('success', true);
  ELSE
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION reset_key(caller_username TEXT, caller_token TEXT, target_key_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; trank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  SELECT COALESCE(rank, 'user') INTO trank FROM license_keys WHERE id = target_key_id;
  IF trank IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF crank = 'owner' THEN
    UPDATE license_keys SET used_by = NULL, session_token = NULL, activated_at = NULL, device_fp = NULL
    WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'reset_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    UPDATE license_keys SET used_by = NULL, session_token = NULL, activated_at = NULL, device_fp = NULL
    WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'reset_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
    UPDATE license_keys SET used_by = NULL, session_token = NULL, activated_at = NULL, device_fp = NULL
    WHERE id = target_key_id;
    PERFORM audit_log(caller_username, 'reset_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    RETURN json_build_object('success', true);
  ELSE
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION delete_key(caller_username TEXT, caller_token TEXT, target_key_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; trank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  SELECT COALESCE(rank, 'user') INTO trank FROM license_keys WHERE id = target_key_id;
  IF trank IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'Not found');
  END IF;
  IF trank = 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Owner key cannot be deleted here');
  END IF;
  IF crank = 'owner' THEN
    PERFORM audit_log(caller_username, 'delete_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    DELETE FROM license_keys WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    PERFORM audit_log(caller_username, 'delete_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    DELETE FROM license_keys WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
    PERFORM audit_log(caller_username, 'delete_key',
      COALESCE((SELECT key FROM license_keys WHERE id = target_key_id), 'key#' || target_key_id::text), '');
    DELETE FROM license_keys WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSE
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION set_rank(caller_username TEXT, caller_token TEXT,
  target_username TEXT, new_rank TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; aff BIGINT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  -- Owner-only, hardcoded (never matrix-grantable: privilege-escalation safety).
  IF crank <> 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF new_rank NOT IN ('user', 'mod', 'admin') THEN
    RETURN json_build_object('success', false, 'error', 'Bad rank');
  END IF;
  IF EXISTS (SELECT 1 FROM license_keys WHERE used_by = target_username AND COALESCE(rank, 'user') = 'owner') THEN
    RETURN json_build_object('success', false, 'error', 'Owner rank cannot be changed here');
  END IF;
  UPDATE license_keys SET rank = new_rank, is_admin = (new_rank = 'admin')
  WHERE used_by = target_username;
  GET DIAGNOSTICS aff = ROW_COUNT;
  IF aff = 0 THEN
    RETURN json_build_object('success', false, 'error', 'No key row matched that user');
  END IF;
  PERFORM audit_log(caller_username, 'set_rank', target_username, 'rank=' || new_rank);
  RETURN json_build_object('success', true);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 5: moderation / blacklist / content / troll / DM RPCs
-- ----------------------------------------------------------------------------
-- Drop pre-upgrade overloads (same names, fewer args) so re-running the
-- migration never leaves two versions behind.
DROP FUNCTION IF EXISTS dm_contacts(TEXT, TEXT);
DROP FUNCTION IF EXISTS dm_thread(TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS dm_send(TEXT, TEXT, TEXT, TEXT);
CREATE OR REPLACE FUNCTION mod_action(caller_username TEXT, caller_token TEXT,
  target_username TEXT, action TEXT, minutes INT DEFAULT 0, reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  crank TEXT;
  trank TEXT;
  until_ts TIMESTAMPTZ;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF target_username IS NULL OR target_username = '' OR target_username = caller_username THEN
    RETURN json_build_object('success', false, 'error', 'Bad target');
  END IF;
  SELECT COALESCE(rank, 'user') INTO trank FROM license_keys WHERE used_by = target_username;
  IF trank IS NULL THEN trank := 'user'; END IF;
  IF trank = 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Owner cannot be moderated here');
  END IF;
  IF crank <> 'owner' THEN
    IF trank = 'user' AND NOT has_perm(crank, 'users.moderate_user') THEN
      RETURN json_build_object('success', false, 'error', 'Insufficient rank');
    ELSIF trank <> 'user' AND NOT has_perm(crank, 'users.moderate_staff') THEN
      RETURN json_build_object('success', false, 'error', 'Insufficient rank');
    END IF;
  END IF;
  IF action = 'warn' THEN
    INSERT INTO warnings (username, reason, warned_by)
    VALUES (target_username, left(COALESCE(reason, ''), 200), caller_username);
    PERFORM audit_log(caller_username, 'warn', target_username, left(COALESCE(reason, ''), 200));
    RETURN json_build_object('success', true);
  ELSIF action = 'mute' THEN
    until_ts := NOW() + (GREATEST(minutes, 1) || ' minutes')::INTERVAL;
    INSERT INTO mutes (username, reason, muted_by, expires_at)
    VALUES (target_username, left(COALESCE(reason, 'Muted by staff'), 200), caller_username, until_ts);
    PERFORM audit_log(caller_username, 'mute', target_username, left(COALESCE(reason, 'Muted by staff'), 200));
    RETURN json_build_object('success', true, 'until', until_ts);
  ELSIF action = 'unmute' THEN
    DELETE FROM mutes WHERE username = target_username AND expires_at > NOW();
    PERFORM audit_log(caller_username, 'unmute', target_username, '');
    RETURN json_build_object('success', true);
  ELSIF action = 'ban' THEN
    until_ts := NOW() + (GREATEST(minutes, 1) || ' minutes')::INTERVAL;
    INSERT INTO game_bans (username, reason, banned_by, expires_at)
    VALUES (target_username, left(COALESCE(reason, 'Banned'), 200), caller_username, until_ts);
    PERFORM audit_log(caller_username, 'game_ban', target_username, left(COALESCE(reason, 'Banned'), 200));
    RETURN json_build_object('success', true, 'until', until_ts);
  ELSE
    RETURN json_build_object('success', false, 'error', 'Bad action');
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION mod_status(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE b JSON; m JSON; s INT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ban', NULL, 'mute', NULL, 'slowmode', 0);
  END IF;
  SELECT json_build_object('expires_at', expires_at, 'reason', reason) INTO b
  FROM game_bans WHERE username = input_username AND expires_at > NOW()
  ORDER BY expires_at DESC LIMIT 1;
  SELECT json_build_object('expires_at', expires_at, 'reason', reason) INTO m
  FROM mutes WHERE username = input_username AND expires_at > NOW()
  ORDER BY expires_at DESC LIMIT 1;
  SELECT slowmode_seconds INTO s FROM chat_settings WHERE id = 1;
  RETURN json_build_object('ban', b, 'mute', m, 'slowmode', COALESCE(s, 0));
END; $$;

CREATE OR REPLACE FUNCTION users_bundle(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.users') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN json_build_object(
    'ranks', COALESCE((SELECT json_object_agg(used_by, COALESCE(rank, 'user'))
      FROM license_keys WHERE used_by IS NOT NULL), '{}'::json),
    'warns', COALESCE((SELECT json_object_agg(username, n) FROM (
      SELECT username, COUNT(*) AS n FROM warnings GROUP BY username) w), '{}'::json),
    'mutes', COALESCE((SELECT json_object_agg(username, expires_at) FROM (
      SELECT DISTINCT ON (username) username, expires_at FROM mutes
      WHERE expires_at > NOW() ORDER BY username, expires_at DESC) m), '{}'::json));
END; $$;

CREATE OR REPLACE FUNCTION bl_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.blacklist') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT id, username, reason, created_at FROM blacklist ORDER BY id DESC LIMIT 200) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION bl_add(caller_username TEXT, caller_token TEXT,
  target_username TEXT, reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF target_username IS NULL OR target_username = '' THEN
    RETURN json_build_object('success', false, 'error', 'Bad username');
  END IF;
  INSERT INTO blacklist (username, reason) VALUES (target_username, left(COALESCE(reason, ''), 200));
  PERFORM audit_log(caller_username, 'blacklist_add', target_username, left(COALESCE(reason, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION bl_remove(caller_username TEXT, caller_token TEXT, target_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  PERFORM audit_log(caller_username, 'blacklist_remove',
    COALESCE((SELECT username FROM blacklist WHERE id = target_id), 'bl#' || target_id::text), '');
  DELETE FROM blacklist WHERE id = target_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION announce_post(caller_username TEXT, caller_token TEXT,
  content TEXT, pinned BOOLEAN DEFAULT false, scheduled_for TIMESTAMPTZ DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; nid BIGINT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'announce.post') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF content IS NULL OR trim(content) = '' THEN
    RETURN json_build_object('success', false, 'error', 'Empty');
  END IF;
  INSERT INTO announcements (content, posted_by, rank, pinned, scheduled_for)
  VALUES (left(trim(content), 500), caller_username, crank, COALESCE(pinned, false), scheduled_for)
  RETURNING id INTO nid;
  RETURN json_build_object('success', true, 'id', nid);
END; $$;

CREATE OR REPLACE FUNCTION announce_delete(caller_username TEXT, caller_token TEXT, target_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'announce.delete') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  DELETE FROM announcements WHERE id = target_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION chat_send(input_username TEXT, input_token TEXT, content TEXT,
  reply_to BIGINT DEFAULT NULL, reply_preview TEXT DEFAULT NULL, reply_username TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  crank TEXT;
  slow INT := 0;
  last_ts TIMESTAMPTZ;
  msg TEXT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = input_username) THEN
    RETURN json_build_object('success', false, 'error', 'blocked');
  END IF;
  IF EXISTS (SELECT 1 FROM mutes WHERE username = input_username AND expires_at > NOW()) THEN
    RETURN json_build_object('success', false, 'error', 'muted');
  END IF;
  SELECT slowmode_seconds INTO slow FROM chat_settings WHERE id = 1;
  IF slow IS NOT NULL AND slow > 0 THEN
    SELECT MAX(created_at) INTO last_ts FROM messages WHERE username = input_username;
    IF last_ts IS NOT NULL AND last_ts > NOW() - (slow || ' seconds')::INTERVAL THEN
      RETURN json_build_object('success', false, 'error', 'slowmode',
        'retry_after', EXTRACT(EPOCH FROM (last_ts + (slow || ' seconds')::INTERVAL - NOW()))::INT);
    END IF;
  END IF;
  msg := left(trim(COALESCE(content, '')), 500);
  IF msg = '' THEN
    RETURN json_build_object('success', false, 'error', 'empty');
  END IF;
  SELECT COALESCE(rank, 'user') INTO crank FROM license_keys WHERE used_by = input_username;
  INSERT INTO messages (username, content, rank, reply_to, reply_preview, reply_username)
  VALUES (input_username, msg, COALESCE(crank, 'user'), reply_to,
    left(COALESCE(reply_preview, ''), 60), reply_username);
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION chat_delete(caller_username TEXT, caller_token TEXT, target_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'chat.delete') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  DELETE FROM messages WHERE id = target_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION troll_fire(caller_username TEXT, caller_token TEXT,
  target_username TEXT, event_type TEXT, payload JSONB DEFAULT '{}')
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'troll.fire') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF event_type NOT IN ('jumpscare','shake','disconnect','flip','ripples','invert',
      'loading','alert','popups','confetti') THEN
    RETURN json_build_object('success', false, 'error', 'Bad trick');
  END IF;
  INSERT INTO troll_events (target_username, event_type, payload)
  VALUES (NULLIF(target_username, ''), event_type, COALESCE(payload, '{}'));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION troll_poll(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN '[]'::json;
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT id, event_type, target_username, payload, created_at
    FROM troll_events ORDER BY id DESC LIMIT 50) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION troll_admin_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.troll') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT id, event_type, target_username, payload, created_at
    FROM troll_events ORDER BY id DESC LIMIT 50) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION dm_send(input_username TEXT, input_token TEXT,
  to_user TEXT, content TEXT, as_user TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE msg TEXT; sender TEXT; crank TEXT;
BEGIN
  sender := COALESCE(NULLIF(as_user, ''), input_username);
  IF sender = input_username THEN
    IF NOT session_user_ok(input_username, input_token) THEN
      RETURN json_build_object('success', false, 'error', 'auth');
    END IF;
  ELSE
    -- Sending as another identity (admin DM panel): staff only.
    crank := caller_rank_of(input_username, input_token);
    IF NOT has_perm(crank, 'tab.users') THEN
      RETURN json_build_object('success', false, 'error', 'auth');
    END IF;
  END IF;
  msg := left(trim(COALESCE(content, '')), 500);
  IF msg = '' OR to_user IS NULL OR to_user = '' THEN
    RETURN json_build_object('success', false, 'error', 'empty');
  END IF;
  INSERT INTO direct_messages (from_username, to_username, content)
  VALUES (sender, to_user, msg);
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION dm_thread(input_username TEXT, input_token TEXT,
  peer TEXT, as_user TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE who TEXT; crank TEXT;
BEGIN
  who := COALESCE(NULLIF(as_user, ''), input_username);
  IF who = input_username THEN
    IF NOT session_user_ok(input_username, input_token) THEN
      RETURN '[]'::json;
    END IF;
  ELSE
    -- Reading another identity's thread (admin DM panel): staff only.
    crank := caller_rank_of(input_username, input_token);
    IF NOT has_perm(crank, 'tab.users') AND NOT has_perm(crank, 'tab.playerdms') THEN
      RETURN '[]'::json;
    END IF;
  END IF;
  UPDATE direct_messages SET read = true
  WHERE from_username = peer AND to_username = who AND read = false;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.created_at) FROM (
    SELECT id, from_username, to_username, content, created_at, read
    FROM direct_messages
    WHERE (from_username = peer AND to_username = who)
       OR (from_username = who AND to_username = peer)
    ORDER BY created_at LIMIT 50) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION dm_contacts(input_username TEXT, input_token TEXT, peer TEXT DEFAULT 'admin')
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.users') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t) FROM (
    SELECT peer_name AS peer, MAX(created_at) AS last_at,
      COUNT(*) FILTER (WHERE NOT read AND to_username = peer) AS unread
    FROM (
      SELECT CASE WHEN from_username = peer THEN to_username ELSE from_username END AS peer_name,
        created_at, read, to_username
      FROM direct_messages WHERE from_username = peer OR to_username = peer
    ) s GROUP BY peer_name ORDER BY last_at DESC LIMIT 50) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION dm_spy_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.playerdms') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.last_at DESC) FROM (
    SELECT LEAST(from_username, to_username) AS u1, GREATEST(from_username, to_username) AS u2,
      MAX(created_at) AS last_at, COUNT(*) AS n,
      (array_agg(content ORDER BY created_at DESC))[1] AS preview
    FROM direct_messages GROUP BY 1, 2 ORDER BY last_at DESC LIMIT 50) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION dm_spy_thread(input_username TEXT, input_token TEXT, u1 TEXT, u2 TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.playerdms') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.created_at) FROM (
    SELECT id, from_username, to_username, content, created_at, read
    FROM direct_messages
    WHERE (from_username = u1 AND to_username = u2) OR (from_username = u2 AND to_username = u1)
    ORDER BY created_at LIMIT 100) t), '[]'::json);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 6: XP / shop / quests / playtime / cosmetics / school RPCs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION xp_earn(input_username TEXT, input_token TEXT,
  earn_amt INT, reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE b INT := 0; l INT := 0; d DATE;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF earn_amt IS NULL OR earn_amt < 1 OR earn_amt > 100 THEN
    RETURN json_build_object('success', false, 'error', 'amount');
  END IF;
  SELECT balance, lifetime INTO b, l FROM xp_balances WHERE username = input_username;
  IF NOT FOUND THEN b := 0; l := 0; END IF;
  b := b + earn_amt; l := l + earn_amt;
  IF EXISTS (SELECT 1 FROM xp_balances WHERE username = input_username) THEN
    UPDATE xp_balances SET balance = b, lifetime = l WHERE username = input_username;
  ELSE
    INSERT INTO xp_balances (username, balance, lifetime) VALUES (input_username, b, l);
  END IF;
  d := CURRENT_DATE;
  IF EXISTS (SELECT 1 FROM xp_daily WHERE username = input_username AND day = d) THEN
    UPDATE xp_daily SET amount = xp_daily.amount + earn_amt
    WHERE username = input_username AND day = d;
  ELSE
    INSERT INTO xp_daily (username, day, amount) VALUES (input_username, d, earn_amt);
  END IF;
  RETURN json_build_object('success', true, 'balance', b, 'lifetime', l);
END; $$;

CREATE OR REPLACE FUNCTION xp_spend(input_username TEXT, input_token TEXT, amount INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE b INT := 0;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF amount IS NULL OR amount < 1 THEN
    RETURN json_build_object('success', false, 'error', 'amount');
  END IF;
  SELECT balance INTO b FROM xp_balances WHERE username = input_username;
  IF NOT FOUND THEN b := 0; END IF;
  IF b < amount THEN
    RETURN json_build_object('success', false, 'error', 'funds', 'balance', b);
  END IF;
  UPDATE xp_balances SET balance = b - amount WHERE username = input_username;
  RETURN json_build_object('success', true, 'balance', b - amount);
END; $$;

CREATE OR REPLACE FUNCTION shop_buy(input_username TEXT, input_token TEXT,
  item_id TEXT, extra TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  b INT := 0;
  price INT;
  msg TEXT;
  until_ts TIMESTAMPTZ;
  crank TEXT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  price := CASE item_id
    WHEN 'shoutout' THEN 100 WHEN 'gold24' THEN 150 WHEN 'status' THEN 200
    WHEN 'sparkle' THEN 250 WHEN 'hideonline' THEN 300 WHEN 'namecolor' THEN 500
    WHEN 'mystery' THEN 100 WHEN 'doubleday' THEN 500 WHEN 'glow' THEN 800
    WHEN 'vipweek' THEN 1000 WHEN 'clearwarn' THEN 2500 ELSE NULL END;
  IF price IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'item');
  END IF;
  SELECT balance INTO b FROM xp_balances WHERE username = input_username;
  IF NOT FOUND THEN b := 0; END IF;
  IF b < price THEN
    RETURN json_build_object('success', false, 'error', 'funds', 'balance', b);
  END IF;
  IF item_id = 'clearwarn' AND NOT EXISTS (SELECT 1 FROM warnings WHERE username = input_username) THEN
    RETURN json_build_object('success', false, 'error', 'nowarn');
  END IF;
  IF item_id = 'shoutout' AND (extra IS NULL OR trim(extra) = '') THEN
    RETURN json_build_object('success', false, 'error', 'empty');
  END IF;
  IF item_id = 'namecolor' AND (extra IS NULL OR extra !~ '^#[0-9a-fA-F]{6}$') THEN
    RETURN json_build_object('success', false, 'error', 'color');
  END IF;
  UPDATE xp_balances SET balance = b - price WHERE username = input_username;
  INSERT INTO xp_purchases (username, item, cost) VALUES (input_username, item_id, price);
  IF NOT EXISTS (SELECT 1 FROM user_cosmetics WHERE username = input_username) THEN
    INSERT INTO user_cosmetics (username) VALUES (input_username);
  END IF;
  IF item_id = 'shoutout' THEN
    SELECT COALESCE(rank, 'user') INTO crank FROM license_keys WHERE used_by = input_username;
    INSERT INTO messages (username, content, rank, shoutout_until)
    VALUES (input_username, left(trim(extra), 200), COALESCE(crank, 'user'), NOW() + INTERVAL '60 seconds');
    msg := 'Shouted!';
  ELSIF item_id = 'gold24' THEN
    UPDATE user_cosmetics SET gold_until = NOW() + INTERVAL '24 hours' WHERE username = input_username; msg := 'Gold for 24h!';
  ELSIF item_id = 'sparkle' THEN
    UPDATE user_cosmetics SET sparkle_until = NOW() + INTERVAL '7 days' WHERE username = input_username; msg := 'Sparkles for a week!';
  ELSIF item_id = 'hideonline' THEN
    UPDATE user_cosmetics SET hide_online = true WHERE username = input_username; msg := 'You are now hidden';
  ELSIF item_id = 'namecolor' THEN
    UPDATE user_cosmetics SET name_color = extra WHERE username = input_username; msg := 'Name color set!';
  ELSIF item_id = 'status' THEN
    UPDATE user_cosmetics SET status = left(COALESCE(extra, ''), 60) WHERE username = input_username; msg := 'Status saved!';
  ELSIF item_id = 'glow' THEN
    UPDATE user_cosmetics SET glow = true WHERE username = input_username; msg := 'Glowing!';
  ELSIF item_id = 'doubleday' THEN
    UPDATE user_cosmetics SET dbl_until = NOW() + INTERVAL '24 hours' WHERE username = input_username; msg := 'Double XP for 24h!';
  ELSIF item_id = 'vipweek' THEN
    UPDATE user_cosmetics SET vip_until = NOW() + INTERVAL '7 days' WHERE username = input_username; msg := 'VIP week!';
  ELSIF item_id = 'mystery' THEN
    IF random() < 0.6 THEN
      UPDATE xp_balances SET balance = balance + 50, lifetime = lifetime + 50 WHERE username = input_username;
      msg := '+50 XP!';
    ELSIF random() < 0.85 THEN
      UPDATE xp_balances SET balance = balance + 150, lifetime = lifetime + 150 WHERE username = input_username;
      msg := '+150 XP!';
    ELSIF random() < 0.95 THEN
      UPDATE user_cosmetics SET gold_until = NOW() + INTERVAL '24 hours' WHERE username = input_username;
      msg := 'Mystery: 24h GOLD!';
    ELSE
      UPDATE user_cosmetics SET dbl_until = NOW() + INTERVAL '24 hours' WHERE username = input_username;
      msg := 'Mystery: DOUBLE XP DAY!';
    END IF;
  ELSIF item_id = 'clearwarn' THEN
    DELETE FROM warnings WHERE id = (
      SELECT id FROM warnings WHERE username = input_username ORDER BY created_at DESC LIMIT 1);
    msg := 'Warning cleared!';
  END IF;
  SELECT balance INTO b FROM xp_balances WHERE username = input_username;
  RETURN json_build_object('success', true, 'balance', b, 'message', msg);
END; $$;

CREATE OR REPLACE FUNCTION quest_claim(input_username TEXT, input_token TEXT,
  qkey TEXT, day_key TEXT, earn_amt INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE b INT := 0; l INT := 0;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF qkey IS NULL OR qkey = '' OR earn_amt IS NULL OR earn_amt < 1 OR earn_amt > 100 THEN
    RETURN json_build_object('success', false, 'error', 'amount');
  END IF;
  IF EXISTS (SELECT 1 FROM quest_claims WHERE username = input_username AND quest_key = qkey AND day = day_key::DATE) THEN
    RETURN json_build_object('success', false, 'error', 'claimed');
  END IF;
  INSERT INTO quest_claims (username, quest_key, day) VALUES (input_username, qkey, day_key::DATE);
  SELECT balance, lifetime INTO b, l FROM xp_balances WHERE username = input_username;
  IF NOT FOUND THEN b := 0; l := 0; END IF;
  b := b + earn_amt; l := l + earn_amt;
  IF EXISTS (SELECT 1 FROM xp_balances WHERE username = input_username) THEN
    UPDATE xp_balances SET balance = b, lifetime = l WHERE username = input_username;
  ELSE
    INSERT INTO xp_balances (username, balance, lifetime) VALUES (input_username, b, l);
  END IF;
  IF EXISTS (SELECT 1 FROM xp_daily WHERE username = input_username AND day = CURRENT_DATE) THEN
    UPDATE xp_daily SET amount = xp_daily.amount + amount WHERE username = input_username AND day = CURRENT_DATE;
  ELSE
    INSERT INTO xp_daily (username, day, amount) VALUES (input_username, CURRENT_DATE, amount);
  END IF;
  RETURN json_build_object('success', true, 'balance', b, 'lifetime', l);
END; $$;

CREATE OR REPLACE FUNCTION game_track(input_username TEXT, input_token TEXT, game_name TEXT, day_key TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ok', false);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM daily_games WHERE username = input_username AND game = game_name AND day = day_key::DATE) THEN
    INSERT INTO daily_games (username, game, day) VALUES (input_username, game_name, day_key::DATE);
  END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION playtime_add(input_username TEXT, input_token TEXT, add_seconds INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE d DATE;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ok', false);
  END IF;
  IF add_seconds IS NULL OR add_seconds < 1 OR add_seconds > 120 THEN
    RETURN json_build_object('ok', false);
  END IF;
  d := CURRENT_DATE;
  IF EXISTS (SELECT 1 FROM daily_playtime WHERE username = input_username AND day = d) THEN
    UPDATE daily_playtime SET seconds = seconds + add_seconds
    WHERE username = input_username AND day = d;
  ELSE
    INSERT INTO daily_playtime (username, day, seconds) VALUES (input_username, d, add_seconds);
  END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION cosmetic_save(input_username TEXT, input_token TEXT, patch JSONB)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF patch IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'empty');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM user_cosmetics WHERE username = input_username) THEN
    INSERT INTO user_cosmetics (username) VALUES (input_username);
  END IF;
  IF patch ? 'status' THEN
    UPDATE user_cosmetics SET status = left(patch->>'status', 60) WHERE username = input_username;
  END IF;
  IF patch ? 'name_color' AND (patch->>'name_color') ~ '^#[0-9a-fA-F]{6}$' THEN
    UPDATE user_cosmetics SET name_color = patch->>'name_color' WHERE username = input_username;
  END IF;
  IF patch ? 'hide_online' AND (patch->>'hide_online') IN ('true', 'false') THEN
    UPDATE user_cosmetics SET hide_online = (patch->>'hide_online')::boolean WHERE username = input_username;
  END IF;
  IF patch ? 'glow' AND (patch->>'glow') IN ('true', 'false') THEN
    UPDATE user_cosmetics SET glow = (patch->>'glow')::boolean WHERE username = input_username;
  END IF;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION school_set(input_username TEXT, input_token TEXT, new_school TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF new_school NOT IN ('SST', 'Lenham') THEN
    RETURN json_build_object('success', false, 'error', 'school');
  END IF;
  UPDATE license_keys SET school = new_school
  WHERE used_by = input_username AND session_token::text = input_token;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION school_mine(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE s TEXT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('school', NULL);
  END IF;
  SELECT school INTO s FROM license_keys
  WHERE used_by = input_username AND session_token::text = input_token;
  RETURN json_build_object('school', s);
END; $$;

CREATE OR REPLACE FUNCTION school_roster()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- Public board data only: never keys, tokens, or fingerprints.
  RETURN COALESCE((SELECT json_agg(t) FROM (
    SELECT used_by, rank, school FROM license_keys WHERE used_by IS NOT NULL LIMIT 500) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION staff_roster()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN COALESCE((SELECT json_agg(t) FROM (
    SELECT used_by, rank FROM license_keys WHERE rank IN ('owner', 'admin', 'mod') LIMIT 100) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION request_admin(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE aff BIGINT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  UPDATE license_keys SET admin_request_status = 'pending'
  WHERE used_by = input_username AND session_token::text = input_token
    AND admin_request_status IS NULL;
  GET DIAGNOSTICS aff = ROW_COUNT;
  IF aff = 0 THEN
    RETURN json_build_object('success', false, 'error', 'used');
  END IF;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION admin_status(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE s TEXT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('status', NULL);
  END IF;
  SELECT admin_request_status INTO s FROM license_keys
  WHERE used_by = input_username AND session_token::text = input_token;
  RETURN json_build_object('status', s);
END; $$;

-- NOTE: an empty token skips the session check (pre-login catch-up on the
-- login screen, keyed by remembered username). Abuse surface is trivial:
-- at most marking someone else's alert seen, which only skips one modal.
CREATE OR REPLACE FUNCTION alerts_check(input_username TEXT, input_token TEXT, ann_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF input_token <> '' AND NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('seen', true);
  END IF;
  RETURN json_build_object('seen', EXISTS (
    SELECT 1 FROM announcement_alerts
    WHERE announcement_id = ann_id AND username = input_username));
END; $$;

CREATE OR REPLACE FUNCTION alerts_add(input_username TEXT, input_token TEXT, ann_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF input_token <> '' AND NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false);
  END IF;
  INSERT INTO announcement_alerts (announcement_id, username)
  VALUES (ann_id, input_username)
  ON CONFLICT (announcement_id, username) DO NOTHING;
  UPDATE announcements SET reminded = true WHERE id = ann_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION friend_add(input_username TEXT, input_token TEXT, target TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false);
  END IF;
  IF target IS NULL OR target = '' OR target = input_username THEN
    RETURN json_build_object('success', false);
  END IF;
  INSERT INTO friends (username, friend) VALUES (input_username, target)
  ON CONFLICT DO NOTHING;
  RETURN json_build_object('success', true);
EXCEPTION WHEN OTHERS THEN
  INSERT INTO friends (username, friend)
  SELECT input_username, target
  WHERE NOT EXISTS (SELECT 1 FROM friends WHERE username = input_username AND friend = target);
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION friend_remove(input_username TEXT, input_token TEXT, target TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false);
  END IF;
  DELETE FROM friends WHERE username = input_username AND friend = target;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION friend_block(input_username TEXT, input_token TEXT, target TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false);
  END IF;
  IF target IS NULL OR target = '' OR target = input_username THEN
    RETURN json_build_object('success', false);
  END IF;
  BEGIN
    INSERT INTO blocks (username, blocked) VALUES (input_username, target)
    ON CONFLICT DO NOTHING;
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO blocks (username, blocked)
    SELECT input_username, target
    WHERE NOT EXISTS (SELECT 1 FROM blocks WHERE username = input_username AND blocked = target);
  END;
  DELETE FROM friends WHERE username = input_username AND friend = target;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION friend_unblock(input_username TEXT, input_token TEXT, target TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false);
  END IF;
  DELETE FROM blocks WHERE username = input_username AND blocked = target;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION friends_mine(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('friends', '[]'::json, 'blocked', '[]'::json);
  END IF;
  RETURN json_build_object(
    'friends', COALESCE((SELECT json_agg(friend) FROM friends WHERE username = input_username LIMIT 100), '[]'::json),
    'blocked', COALESCE((SELECT json_agg(blocked) FROM blocks WHERE username = input_username LIMIT 100), '[]'::json));
END; $$;

CREATE OR REPLACE FUNCTION typing_send(input_username TEXT, input_token TEXT, chan TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('ok', false);
  END IF;
  IF EXISTS (SELECT 1 FROM typing WHERE username = input_username) THEN
    UPDATE typing SET channel = left(COALESCE(chan, ''), 64), updated_at = NOW() WHERE username = input_username;
  ELSE
    INSERT INTO typing (username, channel, updated_at) VALUES (input_username, left(COALESCE(chan, ''), 64), NOW());
  END IF;
  RETURN json_build_object('ok', true);
END; $$;

CREATE OR REPLACE FUNCTION report_submit(input_username TEXT, input_token TEXT,
  reported_user TEXT, message_id BIGINT, reason TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  INSERT INTO reports (reporter, reported_user, message_id, reason, status)
  VALUES (input_username, reported_user, message_id, left(COALESCE(reason, ''), 200), 'pending');
  RETURN json_build_object('success', true);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 7: owner / config / read-bundle RPCs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION slowmode_set(caller_username TEXT, caller_token TEXT, seconds INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tab.messages') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM chat_settings WHERE id = 1) THEN
    INSERT INTO chat_settings (id, slowmode_seconds) VALUES (1, 0);
  END IF;
  UPDATE chat_settings SET slowmode_seconds = GREATEST(COALESCE(seconds, 0), 0) WHERE id = 1;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION scare_set(caller_username TEXT, caller_token TEXT, image_data TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'troll.custom_image') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF image_data IS NOT NULL AND length(image_data) > 700000 THEN
    RETURN json_build_object('success', false, 'error', 'too-big');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM troll_settings WHERE id = 1) THEN
    INSERT INTO troll_settings (id, jumpscare_image) VALUES (1, NULL);
  END IF;
  UPDATE troll_settings SET jumpscare_image = image_data WHERE id = 1;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION perms_set(caller_username TEXT, caller_token TEXT,
  target_rank TEXT, new_perms JSONB)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF caller_rank_of(caller_username, caller_token) <> 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF target_rank NOT IN ('admin', 'mod') OR new_perms IS NULL THEN
    RETURN json_build_object('success', false, 'error', 'bad');
  END IF;
  IF EXISTS (SELECT 1 FROM rank_perms WHERE rank = target_rank) THEN
    UPDATE rank_perms SET perms = new_perms WHERE rank = target_rank;
  ELSE
    INSERT INTO rank_perms (rank, perms) VALUES (target_rank, new_perms);
  END IF;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION perms_clear(caller_username TEXT, caller_token TEXT, target_rank TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF caller_rank_of(caller_username, caller_token) <> 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  DELETE FROM rank_perms WHERE rank = target_rank;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION lock_set(caller_username TEXT, caller_token TEXT,
  new_locked BOOLEAN, new_message TEXT DEFAULT '')
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF caller_rank_of(caller_username, caller_token) <> 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app_config WHERE id = 1) THEN
    INSERT INTO app_config (id, locked, lock_message) VALUES (1, new_locked, left(COALESCE(new_message, ''), 200));
  ELSE
    UPDATE app_config SET locked = new_locked, lock_message = left(COALESCE(new_message, ''), 200) WHERE id = 1;
  END IF;
  PERFORM audit_log(caller_username, CASE WHEN new_locked THEN 'site_lock' ELSE 'site_unlock' END,
    'site', left(COALESCE(new_message, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION xp_grant(caller_username TEXT, caller_token TEXT,
  target_username TEXT, amount INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; b INT := 0; l INT := 0;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'users.give_xp') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF target_username IS NULL OR target_username = '' OR amount IS NULL OR amount < 1 OR amount > 100000 THEN
    RETURN json_build_object('success', false, 'error', 'amount');
  END IF;
  SELECT balance, lifetime INTO b, l FROM xp_balances WHERE username = target_username;
  IF NOT FOUND THEN b := 0; l := 0; END IF;
  b := b + amount; l := l + amount;
  IF EXISTS (SELECT 1 FROM xp_balances WHERE username = target_username) THEN
    UPDATE xp_balances SET balance = b, lifetime = l WHERE username = target_username;
  ELSE
    INSERT INTO xp_balances (username, balance, lifetime) VALUES (target_username, b, l);
  END IF;
  INSERT INTO xp_purchases (username, item, cost) VALUES (target_username, 'grant', 0);
  RETURN json_build_object('success', true, 'balance', b);
END; $$;

CREATE OR REPLACE FUNCTION xp_grant_all(caller_username TEXT, caller_token TEXT,
  which TEXT, amount INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  crank TEXT;
  names TEXT[];
  n TEXT;
  c INT := 0;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'users.give_xp') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  IF amount IS NULL OR amount < 1 OR amount > 100000 THEN
    RETURN json_build_object('success', false, 'error', 'amount');
  END IF;
  IF which = 'online' THEN
    SELECT COALESCE(array_agg(username), '{}') INTO names FROM active_sessions
    WHERE last_seen > NOW() - INTERVAL '90 seconds';
  ELSE
    SELECT COALESCE(array_agg(DISTINCT used_by), '{}') INTO names FROM license_keys
    WHERE used_by IS NOT NULL;
  END IF;
  FOREACH n IN ARRAY names LOOP
    IF EXISTS (SELECT 1 FROM xp_balances WHERE username = n) THEN
      UPDATE xp_balances SET balance = balance + amount, lifetime = lifetime + amount WHERE username = n;
    ELSE
      INSERT INTO xp_balances (username, balance, lifetime) VALUES (n, amount, amount);
    END IF;
    c := c + 1;
  END LOOP;
  RETURN json_build_object('success', true, 'count', c);
END; $$;

CREATE OR REPLACE FUNCTION dashboard_stats(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; k BIGINT; u BIGINT; o BIGINT; p BIGINT; rp BIGINT; rep BIGINT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.dashboard') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  SELECT COUNT(*) INTO k FROM license_keys WHERE is_active = true;
  SELECT COUNT(*) INTO u FROM license_keys WHERE used_by IS NOT NULL;
  SELECT COUNT(*) INTO o FROM active_sessions WHERE last_seen > NOW() - INTERVAL '90 seconds';
  SELECT COUNT(*) INTO p FROM key_requests WHERE status = 'pending';
  SELECT COUNT(*) INTO rp FROM key_reset_requests WHERE status = 'pending';
  SELECT COUNT(*) INTO rep FROM reports WHERE COALESCE(status, 'pending') = 'pending';
  RETURN json_build_object('keys', k, 'used', u, 'online', o, 'pending', p,
    'resets_pending', rp, 'reports_pending', rep);
END; $$;

CREATE OR REPLACE FUNCTION activity_feed(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.activity') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(u) FROM (SELECT * FROM (
    SELECT activated_at AS when_ts, 'activation'::TEXT AS kind,
      (COALESCE(used_by, 'unknown') || ' activated a key') AS detail
    FROM license_keys WHERE used_by IS NOT NULL
    UNION ALL
    SELECT created_at AS when_ts, 'blacklist'::TEXT AS kind,
      (COALESCE(username, 'unknown') || ' blacklisted' ||
        CASE WHEN reason IS NOT NULL AND reason <> '' THEN ' â€” ' || reason ELSE '' END) AS detail
    FROM blacklist
    UNION ALL
    SELECT created_at AS when_ts, ('troll: ' || COALESCE(event_type, '?')) AS kind,
      ('â†’ ' || COALESCE(target_username, 'Everyone')) AS detail
    FROM troll_events
    UNION ALL
    SELECT status_updated_at AS when_ts, ('request ' || COALESCE(status, '?')) AS kind,
      (COALESCE(name, 'unknown') || ' â€” request ' || COALESCE(status, '?')) AS detail
    FROM key_requests WHERE status IN ('approved', 'denied')
  ) t ORDER BY t.when_ts DESC NULLS LAST LIMIT 80) u), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION keys_ranks(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'users.set_rank') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_object_agg(used_by, COALESCE(rank, 'user'))
    FROM license_keys WHERE used_by IS NOT NULL), '{}'::json);
END; $$;

CREATE OR REPLACE FUNCTION watch_get(input_username TEXT, input_token TEXT, target TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'users.watch') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN json_build_object(
    'sessions', COALESCE((SELECT json_agg(s) FROM (
      SELECT username, current_game, last_seen FROM active_sessions WHERE username = target) s), '[]'::json),
    'key', COALESCE((SELECT row_to_json(k) FROM (
      SELECT used_by, rank, school, admin_request_status, activated_at FROM license_keys WHERE used_by = target LIMIT 1) k), 'null'::json),
    'playtime', COALESCE((SELECT json_agg(p) FROM (
      SELECT day, seconds FROM daily_playtime WHERE username = target ORDER BY day DESC LIMIT 7) p), '[]'::json),
    'xp', COALESCE((SELECT row_to_json(x) FROM (
      SELECT balance, lifetime FROM xp_balances WHERE username = target) x), 'null'::json),
    'warnings', COALESCE((SELECT json_agg(w ORDER BY w.created_at DESC) FROM (
      SELECT id, reason, created_at FROM warnings WHERE username = target ORDER BY created_at DESC LIMIT 5) w), '[]'::json),
    'mute', (SELECT row_to_json(m) FROM (
      SELECT reason, expires_at FROM mutes WHERE username = target AND expires_at > NOW()
      ORDER BY expires_at DESC LIMIT 1) m),
    'ban', (SELECT row_to_json(b) FROM (
      SELECT reason, expires_at FROM game_bans WHERE username = target AND expires_at > NOW()
      ORDER BY expires_at DESC LIMIT 1) b),
    'messages', COALESCE((SELECT json_agg(m ORDER BY m.created_at DESC) FROM (
      SELECT content, created_at FROM messages WHERE username = target ORDER BY created_at DESC LIMIT 5) m), '[]'::json),
    'trolls', COALESCE((SELECT json_agg(t ORDER BY t.created_at DESC) FROM (
      SELECT event_type, payload, created_at FROM troll_events WHERE target_username = target
      ORDER BY created_at DESC LIMIT 5) t), '[]'::json));
END; $$;

CREATE OR REPLACE FUNCTION reports_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.reports') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT id, reporter, reported_user, message_id, reason, status, created_at
    FROM reports ORDER BY id DESC LIMIT 100) t), '[]'::json);
END; $$;

CREATE OR REPLACE FUNCTION report_dismiss(caller_username TEXT, caller_token TEXT, report_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tab.reports') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  UPDATE reports SET status = 'dismissed' WHERE id = report_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION report_action(caller_username TEXT, caller_token TEXT, report_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'tab.reports') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  UPDATE reports SET status = 'actioned' WHERE id = report_id;
  RETURN json_build_object('success', true);
END; $$;

CREATE TABLE IF NOT EXISTS game_ratings (
  username TEXT NOT NULL,
  game_slug TEXT NOT NULL,
  rating SMALLINT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (username, game_slug)
);

-- Thumbs up (+1), down (-1), or 0 to clear. One row per player per game.
CREATE OR REPLACE FUNCTION rate_game(input_username TEXT, input_token TEXT,
  game_slug TEXT, stars INT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE ups INT; downs INT; mine INT;
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('success', false, 'error', 'auth');
  END IF;
  IF game_slug IS NULL OR trim(game_slug) = '' OR length(game_slug) > 64 THEN
    RETURN json_build_object('success', false, 'error', 'Bad game');
  END IF;
  IF stars IS NULL OR stars NOT IN (-1, 0, 1) THEN
    RETURN json_build_object('success', false, 'error', 'Bad rating');
  END IF;
  IF stars = 0 THEN
    DELETE FROM game_ratings WHERE username = input_username AND game_ratings.game_slug = rate_game.game_slug;
  ELSE
    INSERT INTO game_ratings (username, game_slug, rating, updated_at)
    VALUES (input_username, trim(game_slug), stars, NOW())
    ON CONFLICT (username, game_slug)
    DO UPDATE SET rating = EXCLUDED.rating, updated_at = NOW();
  END IF;
  SELECT COUNT(*) FILTER (WHERE rating = 1), COUNT(*) FILTER (WHERE rating = -1),
    COALESCE(MAX(rating) FILTER (WHERE username = input_username), 0)
  INTO ups, downs, mine FROM game_ratings WHERE game_ratings.game_slug = rate_game.game_slug;
  RETURN json_build_object('success', true, 'up', ups, 'down', downs, 'mine', mine);
END; $$;

-- Top-3 most liked (30d? no — all-time score) + most played (30d plays).
CREATE OR REPLACE FUNCTION game_tops(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT session_user_ok(input_username, input_token) THEN
    RETURN json_build_object('error', 'auth');
  END IF;
  RETURN json_build_object(
    'liked', COALESCE((SELECT json_agg(t) FROM (
      SELECT game_slug, COUNT(*) FILTER (WHERE rating = 1) AS up,
        COUNT(*) FILTER (WHERE rating = -1) AS down
      FROM game_ratings GROUP BY game_slug
      HAVING COUNT(*) FILTER (WHERE rating = 1) > 0
      ORDER BY COUNT(*) FILTER (WHERE rating = 1) DESC,
        COUNT(*) FILTER (WHERE rating = -1) ASC LIMIT 3) t), '[]'::json),
    'played', COALESCE((SELECT json_agg(t) FROM (
      SELECT game AS game_slug, COUNT(*) AS plays FROM daily_games
      WHERE day > CURRENT_DATE - 30 GROUP BY game ORDER BY plays DESC LIMIT 3) t), '[]'::json),
    'mine', COALESCE((SELECT json_object_agg(game_slug, rating) FROM game_ratings
      WHERE username = input_username), '{}'::json));
END; $$;

-- Staff audit trail: every privileged action lands here (who did what to
-- whom, when). Append-only: no UPDATE/DELETE path exists anywhere, rows
-- auto-prune after 90 days. Direct calls are revoked below (after STEP 8)
-- so entries can only be written by the RPCs themselves, never forged.
CREATE OR REPLACE FUNCTION audit_log(actor TEXT, action TEXT, target TEXT, detail TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO staff_audit (actor, action, target, detail)
  VALUES (left(COALESCE(actor, ''), 64), left(COALESCE(action, ''), 64),
    left(COALESCE(target, ''), 200), left(COALESCE(detail, ''), 500));
  DELETE FROM staff_audit WHERE created_at < NOW() - INTERVAL '90 days';
EXCEPTION WHEN undefined_table THEN NULL;
END; $$;

CREATE OR REPLACE FUNCTION audit_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF caller_rank_of(input_username, input_token) <> 'owner' THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.id DESC) FROM (
    SELECT id, actor, action, target, detail, created_at FROM staff_audit
    ORDER BY id DESC LIMIT 200
  ) t), '[]'::json);
END; $$;

-- Schema version: bump the number every time this file changes behavior.
-- Clients compare it on load and warn when the database is behind, so a
-- forgotten re-run shows up as a banner instead of mystery failures.
CREATE OR REPLACE FUNCTION schema_version()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN json_build_object('success', true, 'v', 2);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 8: lock down function execution — anon may call ONLY these RPCs.
-- ----------------------------------------------------------------------------
DO $$
DECLARE f TEXT;
BEGIN
  FOR f IN SELECT p.oid::regprocedure::TEXT FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
        AND p.proname IN ('caller_rank_of','has_perm','session_user_ok',
        'schema_version',
        'validate_key','verify_session','submit_key_request','check_request_status',
        'presence_upsert','presence_touch','req_list','approve_key_request','deny_key_request',
        'adminreq_list','adminreq_decide','keys_list','key_create_bulk','toggle_key','reset_key',
        'delete_key','set_rank','mod_action','mod_status','users_bundle','bl_list','bl_add','bl_remove',
        'announce_post','announce_delete','chat_send','chat_delete','troll_fire','troll_poll',
        'troll_admin_list','dm_send','dm_thread','dm_contacts','dm_spy_list','dm_spy_thread',
        'xp_earn','xp_spend','shop_buy','quest_claim','game_track','playtime_add','cosmetic_save',
        'school_set','school_mine','school_roster','staff_roster','request_admin','admin_status',
        'alerts_check','alerts_add','friend_add','friend_remove','friend_block','friend_unblock',
        'friends_mine','typing_send','report_submit','slowmode_set','scare_set','perms_set',
        'perms_clear','lock_set','xp_grant','xp_grant_all','dashboard_stats','activity_feed',
        'keys_ranks','watch_get','reports_list','report_dismiss','report_action',
        'wall_check','user_delete','block_device_by_key','unblock_device','devices_list',
        'reset_my_key','block_requester_device','logout_session',
        'submit_reset_request','check_reset_status','resetreq_list',
        'resetreq_approve','resetreq_deny','audit_list',
        'tourney_create','tourney_list','tourney_detail','tourney_join',
        'tourney_start','tourney_decide','tourney_cancel',
        'shootout_pick','shootout_state','tourney_submit',
        'tourney_add','tourney_myturn',
        'rate_game','game_tops')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO anon', f);
  END LOOP;
END $$;

-- audit_log is write-only infrastructure: callable from other RPCs only,
-- never directly (otherwise anyone could forge staff-action entries).
REVOKE ALL ON FUNCTION audit_log(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;

-- ----------------------------------------------------------------------------
-- STEP 9: device blacklist + site-wide wall + user deletion
-- ----------------------------------------------------------------------------
-- Site-wide wall: checked on EVERY page (even pre-login) by remembered
-- username + device fingerprint. No auth needed by design; worst abuse is
-- learning whether a name/fp is blocked (trivial, non-sensitive).
CREATE OR REPLACE FUNCTION wall_check(input_username TEXT, input_fp TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF input_username IS NOT NULL AND input_username <> '' AND EXISTS (
    SELECT 1 FROM blacklist WHERE username = input_username) THEN
    RETURN json_build_object('blocked', true);
  END IF;
  IF input_fp IS NOT NULL AND input_fp <> '' AND EXISTS (
    SELECT 1 FROM blacklist_devices WHERE fp = input_fp) THEN
    RETURN json_build_object('blocked', true);
  END IF;
  RETURN json_build_object('blocked', false);
END; $$;

-- Self-service key reset: name + key must match the bound account, and a
-- session must currently be active (otherwise just log in). Clears the
-- session instantly so the owner can log straight back in. The name binding
-- is preserved. Key + exact name = full control: share them and you share
-- the account — reset wars are settled by staff (Reset + blacklist).
CREATE OR REPLACE FUNCTION reset_my_key(input_name TEXT, input_key TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- REMOVED: instant self-service reset let anyone holding a leaked
  -- name+key steal the live session. Resets now go through staff approval
  -- (submit_reset_request -> resetreq_approve). This stub exists only so
  -- old clients get a clear answer instead of a missing-function error.
  RETURN json_build_object('success', false, 'error', 'staff_only');
END; $$;

-- Full user deletion: keys, sessions, presence. Content/history stays.
CREATE OR REPLACE FUNCTION user_delete(caller_username TEXT, caller_token TEXT,
  target_username TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; trank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF target_username IS NULL OR target_username = '' OR target_username = caller_username THEN
    RETURN json_build_object('success', false, 'error', 'Bad target');
  END IF;
  SELECT COALESCE(rank, 'user') INTO trank FROM license_keys WHERE used_by = target_username;
  IF trank IS NULL THEN trank := 'user'; END IF;
  IF trank = 'owner' THEN
    RETURN json_build_object('success', false, 'error', 'Owner cannot be deleted here');
  END IF;
  IF crank <> 'owner' THEN
    IF trank = 'user' AND NOT has_perm(crank, 'keys.modify_user') THEN
      RETURN json_build_object('success', false, 'error', 'Insufficient rank');
    ELSIF trank <> 'user' AND NOT has_perm(crank, 'keys.modify_staff') THEN
      RETURN json_build_object('success', false, 'error', 'Insufficient rank');
    END IF;
  END IF;
  PERFORM audit_log(caller_username, 'user_delete', target_username, '');
  DELETE FROM active_sessions WHERE username = target_username;
  DELETE FROM license_keys WHERE used_by = target_username;
  RETURN json_build_object('success', true);
END; $$;

-- Block the device currently tied to a key (fingerprint never leaves the DB).
CREATE OR REPLACE FUNCTION block_device_by_key(caller_username TEXT, caller_token TEXT,
  target_key_id BIGINT, reason TEXT DEFAULT NULL)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT; f TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  SELECT device_fp INTO f FROM license_keys WHERE id = target_key_id;
  IF f IS NULL OR f = '' THEN
    RETURN json_build_object('success', false, 'error', 'no-device');
  END IF;
  INSERT INTO blacklist_devices (fp, reason)
  VALUES (f, left(COALESCE(reason, ''), 200))
  ON CONFLICT (fp) DO NOTHING;
  PERFORM audit_log(caller_username, 'block_device', 'key#' || target_key_id::text, left(COALESCE(reason, ''), 200));
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION unblock_device(caller_username TEXT, caller_token TEXT, fp TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(caller_username, caller_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('success', false, 'error', 'Insufficient rank');
  END IF;
  PERFORM audit_log(caller_username, 'unblock_device', '…' || right(fp, 8), '');
  DELETE FROM blacklist_devices WHERE blacklist_devices.fp = unblock_device.fp;
  RETURN json_build_object('success', true);
END; $$;

CREATE OR REPLACE FUNCTION devices_list(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE crank TEXT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'blacklist.manage') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  RETURN COALESCE((SELECT json_agg(t ORDER BY t.created_at DESC) FROM (
    SELECT fp, reason, created_at FROM blacklist_devices ORDER BY created_at DESC LIMIT 100) t), '[]'::json);
END; $$;

-- ----------------------------------------------------------------------------
-- STEP 10: lockdown for tables created after the STEP 1 loop.
-- (The STEP 1 loop only covers tables that exist when it runs; anything
-- created later keeps Postgres' default open access unless locked here.
-- key_reset_requests holds name+key plaintext: must NOT stay open.)
-- ----------------------------------------------------------------------------
DO $$
DECLARE
  t TEXT;
  tbls2 TEXT[] := ARRAY[
    'key_reset_requests', 'staff_audit',
    'tournaments', 'tournament_entries', 'tournament_matches',
    'shootout_picks', 'game_ratings'
  ];
  pol RECORD;
BEGIN
  FOREACH t IN ARRAY tbls2 LOOP
    BEGIN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
      FOR pol IN SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = t LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', pol.policyname, t);
      END LOOP;
      EXECUTE format('REVOKE ALL ON public.%I FROM anon, authenticated', t);
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'late lockdown skipped for %: %', t, SQLERRM;
    END;
  END LOOP;
END $$;
