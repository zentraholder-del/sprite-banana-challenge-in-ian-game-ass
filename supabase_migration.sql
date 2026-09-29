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

    'xp_daily', 'xp_purchases', 'mutes'

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

      'announce.post','announce.delete','chat.delete','blacklist.manage','troll.fire');

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
  IF EXISTS (SELECT 1 FROM blacklist WHERE username = input_username) THEN
    RETURN json_build_object('success', false, 'error', 'blacklisted');
  END IF;
  SELECT * INTO r FROM license_keys WHERE key = upper(trim(input_key));
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
  -- Strict device check: a recorded fingerprint must match exactly. A missing
  -- client fingerprint cannot bypass it (else anyone could pass NULL).
  IF r.device_fp IS NOT NULL AND (input_fp IS NULL OR input_fp = '' OR r.device_fp <> input_fp) THEN
    RETURN json_build_object('success', false, 'error', 'other_device');
  END IF;
  new_token := gen_random_uuid();
  UPDATE license_keys
  SET session_token = new_token,
      used_by = COALESCE(r.used_by, input_username),
      activated_at = COALESCE(activated_at, NOW()),
      device_fp = COALESCE(NULLIF(input_fp, ''), device_fp)
  WHERE id = r.id;
  RETURN json_build_object('success', true, 'rank', crank, 'is_admin', r.is_admin,
    'session_token', new_token, 'welcome_back', (r.session_token IS NOT NULL));
END; $$;

CREATE OR REPLACE FUNCTION verify_session(input_username TEXT, input_token TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE r license_keys%ROWTYPE;
BEGIN
  SELECT * INTO r FROM license_keys
  WHERE session_token::text = input_token
    AND (input_username = '' OR used_by = input_username)
    AND is_active = true;
  IF NOT FOUND THEN
    RETURN json_build_object('valid', false);
  END IF;
  RETURN json_build_object('valid', true, 'used_by', r.used_by,
    'rank', COALESCE(r.rank, CASE WHEN r.is_admin THEN 'admin' ELSE 'user' END),
    'is_admin', r.is_admin);
END; $$;

CREATE OR REPLACE FUNCTION submit_key_request(input_name TEXT, input_reason TEXT, input_school TEXT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE prev key_requests%ROWTYPE;
BEGIN
  SELECT * INTO prev FROM key_requests WHERE name = input_name ORDER BY id DESC LIMIT 1;
  IF FOUND AND prev.status = 'pending' THEN
    RETURN json_build_object('success', false, 'error', 'pending');
  END IF;
  IF FOUND AND prev.created_at IS NOT NULL AND prev.created_at > NOW() - INTERVAL '24 hours' THEN
    RETURN json_build_object('success', false, 'error', 'cooldown',
      'retry_after', EXTRACT(EPOCH FROM (prev.created_at + INTERVAL '24 hours' - NOW()))::BIGINT);
  END IF;
  INSERT INTO key_requests (name, reason, school, status)
  VALUES (input_name, input_reason, NULLIF(input_school, ''), 'pending');
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
      SELECT id, name, reason, school, status, created_at, status_updated_at, deny_reason
      FROM key_requests ORDER BY id DESC LIMIT 100
    ) t
  ), '[]'::json);
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
  RETURN json_build_object('success', true);
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
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    UPDATE license_keys SET is_active = next_active WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
    UPDATE license_keys SET is_active = next_active WHERE id = target_key_id;
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
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    UPDATE license_keys SET used_by = NULL, session_token = NULL, activated_at = NULL, device_fp = NULL
    WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
    UPDATE license_keys SET used_by = NULL, session_token = NULL, activated_at = NULL, device_fp = NULL
    WHERE id = target_key_id;
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
    DELETE FROM license_keys WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank = 'user' AND has_perm(crank, 'keys.modify_user') THEN
    DELETE FROM license_keys WHERE id = target_key_id;
    RETURN json_build_object('success', true);
  ELSIF trank <> 'user' AND has_perm(crank, 'keys.modify_staff') THEN
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
    RETURN json_build_object('success', true);
  ELSIF action = 'mute' THEN
    until_ts := NOW() + (GREATEST(minutes, 1) || ' minutes')::INTERVAL;
    INSERT INTO mutes (username, reason, muted_by, expires_at)
    VALUES (target_username, left(COALESCE(reason, 'Muted by staff'), 200), caller_username, until_ts);
    RETURN json_build_object('success', true, 'until', until_ts);
  ELSIF action = 'unmute' THEN
    DELETE FROM mutes WHERE username = target_username AND expires_at > NOW();
    RETURN json_build_object('success', true);
  ELSIF action = 'ban' THEN
    until_ts := NOW() + (GREATEST(minutes, 1) || ' minutes')::INTERVAL;
    INSERT INTO game_bans (username, reason, banned_by, expires_at)
    VALUES (target_username, left(COALESCE(reason, 'Banned'), 200), caller_username, until_ts);
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
DECLARE crank TEXT; k BIGINT; u BIGINT; o BIGINT; p BIGINT;
BEGIN
  crank := caller_rank_of(input_username, input_token);
  IF NOT has_perm(crank, 'tab.dashboard') THEN
    RETURN json_build_object('error', 'rank');
  END IF;
  SELECT COUNT(*) INTO k FROM license_keys WHERE is_active = true;
  SELECT COUNT(*) INTO u FROM license_keys WHERE used_by IS NOT NULL;
  SELECT COUNT(*) INTO o FROM active_sessions WHERE last_seen > NOW() - INTERVAL '90 seconds';
  SELECT COUNT(*) INTO p FROM key_requests WHERE status = 'pending';
  RETURN json_build_object('keys', k, 'used', u, 'online', o, 'pending', p);
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

-- ----------------------------------------------------------------------------
-- STEP 8: lock down function execution â€” anon may call ONLY these RPCs.
-- ----------------------------------------------------------------------------
DO $$
DECLARE f TEXT;
BEGIN
  FOR f IN SELECT p.oid::regprocedure::TEXT FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN ('caller_rank_of','has_perm','session_user_ok',
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
        'keys_ranks','watch_get','reports_list','report_dismiss','report_action')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO anon', f);
  END LOOP;
END $$;
