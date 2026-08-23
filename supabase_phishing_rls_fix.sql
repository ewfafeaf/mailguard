-- MailGuard/NonDox: close phishing_targets/phishing_campaigns write hole via RPC
-- APPLIED to project qalcsmnvyuujsmnreglt on 2026-08-23 via Supabase MCP,
-- after testing inside BEGIN...ROLLBACK transactions and a real end-to-end
-- smoke test (anon-role RPC call against a live "test" campaign target,
-- verified, then manually reverted — clicked/clicked_at/click_count are
-- back to their original values). Spusti v Supabase SQL Editore len ak
-- potrebuješ replikovať na inom projekte — na produkcii je toto už live.
--
-- Background (verified against live DB before writing this):
--   - SELECT was already correctly owner-scoped on both tables
--     (owner_all_campaigns, owner_all_targets, select_own_targets) — no
--     change needed there.
--   - The real hole was two UPDATE policies with USING(true)/no row filter
--     at all: allow_track_update (phishing_campaigns) and track_by_token
--     (phishing_targets). Anyone holding the public anon key could PATCH
--     any row in either table directly against PostgREST, corrupting click
--     stats/target data across every school's campaigns, and — via
--     Prefer: return=representation — read back member_email/token/etc.
--     for rows they had no business touching.
--   - Table-level grants for anon/authenticated were also blanket (every
--     column, SELECT+UPDATE+INSERT+REFERENCES) — not touched by this file,
--     since the RPC approach below makes those grants moot for writes:
--     the RPC is SECURITY DEFINER and does the write internally, so anon
--     no longer needs any UPDATE privilege on these tables at all once the
--     two policies below are dropped.

-- 1. RPC function — the only path for recording a click going forward.
--    Looks up the target strictly by its own token (SECURITY DEFINER lets
--    it bypass RLS internally for that one lookup+write; the calling role
--    itself gets no broader access). Writes ONLY clicked + clicked_at on
--    the matched target, plus increments the owning campaign's
--    click_count — nothing else, no arbitrary column writes.
CREATE OR REPLACE FUNCTION public.track_phishing_click(p_token text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $func$
DECLARE
  v_target_id uuid;
  v_campaign_id uuid;
  v_already_clicked boolean;
BEGIN
  SELECT id, campaign_id, clicked INTO v_target_id, v_campaign_id, v_already_clicked
  FROM public.phishing_targets
  WHERE token = p_token
  LIMIT 1;

  IF v_target_id IS NULL THEN
    RETURN false;
  END IF;

  IF v_already_clicked THEN
    RETURN true; -- idempotent: repeat clicks on the same link are a no-op
  END IF;

  UPDATE public.phishing_targets
  SET clicked = true, clicked_at = now()
  WHERE id = v_target_id;

  UPDATE public.phishing_campaigns
  SET click_count = click_count + 1
  WHERE id = v_campaign_id;

  RETURN true;
END;
$func$;

GRANT EXECUTE ON FUNCTION public.track_phishing_click(text) TO anon, authenticated;

-- 2. Drop the unrestricted UPDATE policies — the RPC above is now the only
--    write path anon needs, and it bypasses these via SECURITY DEFINER.
DROP POLICY IF EXISTS "allow_track_update" ON public.phishing_campaigns;
DROP POLICY IF EXISTS "track_by_token" ON public.phishing_targets;

-- ── TESTED before applying, inside BEGIN...ROLLBACK (run twice, on two
--    different fresh unclicked targets, immediately before this was
--    made permanent) ──
--   1. Valid-token click via the RPC, as anon: clicked=true + clicked_at
--      set correctly, campaign click_count incremented. ✓
--   2. Direct anon UPDATE to phishing_targets.member_email (bypassing the
--      RPC entirely): zero effect — no permissive policy left. ✓ blocked
--   3. Unrelated authenticated user (not a campaign owner): SELECT on
--      phishing_targets returns 0 rows; UPDATE clicked=false has zero
--      effect. ✓ blocked
-- All three ran in a single rolled-back transaction each time — no
-- permanent change from the rehearsals.
--
-- ── REAL SMOKE TEST after applying (not rolled back) ──
-- Called track_phishing_click() as anon against a live "test" campaign's
-- unclicked target (id ca7445d9-6691-4970-9b63-12e419507184): returned
-- true, clicked/clicked_at were set, campaign click_count went 0→1 —
-- all confirmed via direct SELECT. Then manually reverted (clicked=false,
-- clicked_at=null, click_count=0) to restore the exact original state.

-- ── NOT covered by this file ──
-- api/phishing-track.js was rewritten to call this RPC via
-- /rest/v1/rpc/track_phishing_click instead of doing a direct SELECT+PATCH
-- with SUPABASE_SERVICE_KEY||SUPABASE_ANON_KEY. As a consequence, the old
-- bot-detection/geo-lookup logic (ip/country/behavior/notes) was removed —
-- it wrote to columns (user_agent, ip_address, country, country_code,
-- is_suspicious, notes) that don't exist on phishing_targets in this
-- schema and never actually persisted anything. Flagging this as a
-- separate, pre-existing schema-drift bug, not something reintroduced
-- here — if that enrichment data is wanted, it needs real columns added
-- and the RPC extended to accept/store them, which is out of scope for
-- this security fix.
