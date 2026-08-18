-- MailGuard/NonDox: analyses table RLS fix — owner-based team visibility
-- Applied directly to project qalcsmnvyuujsmnreglt via Supabase MCP on 2026-08-18.
-- Spusti v Supabase SQL Editore len ak potrebuješ replikovať na inom projekte
-- (napr. nový dev/staging projekt) — na produkcii je toto už live.

-- 1. Zmaž pôvodnú SELECT policy (inline OR/EXISTS verzia)
DROP POLICY IF EXISTS "Users see own analyses" ON public.analyses;

-- 2. Bezpečná helper funkcia (SECURITY DEFINER obchádza RLS rekurziu pri
--    dotaze do team_members zvnútra policy na analyses).
--
--    DÔLEŽITÉ: smer vzťahu owner/member. Súčasný viditeľ (auth.uid()) musí
--    byť team owner a kontrolovaný riadok (scan_owner) musí patriť jeho
--    joined členovi — NIE naopak. Prvá verzia tejto funkcie mala smer
--    obrátený (member videl owner-a namiesto owner videl member-a) — chyba
--    zachytená testom pred nasadením, opravené pred touto verziou.
CREATE OR REPLACE FUNCTION public.is_team_member_of(scan_owner uuid)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER STABLE
SET search_path = public
AS $$
  SELECT
    scan_owner = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.team_members tm
      WHERE tm.owner_id = auth.uid()
        AND tm.member_user_id = scan_owner
        AND tm.status = 'joined'
    );
$$;

-- 3. Nová SELECT policy: vidíš svoje analýzy + analýzy joined členov tímu
--    (ak si owner). status hodnoty v tejto schéme sú 'invited'/'joined'
--    (nie 'active' — over si to pred kopírovaním do iného projektu).
CREATE POLICY "analyses_select_own_or_team" ON public.analyses
  FOR SELECT USING ( public.is_team_member_of(user_id) );

-- ── OTESTOVANÉ pred commitom (simulácia auth.uid() cez SET LOCAL
--    request.jwt.claims, nie cez privilegovaný service-role prístup):
--   1. Bežný user (82de1f37…, 10 vlastných riadkov) → vidí presne 10, len svoje.
--   2. Pozvaný, ale ešte NIE joined člen tímu (772f2068…) → vidí len svoj
--      1 riadok, NEvidí owner-ove riadky (status='invited' correctly blocks).
--   3. Owner (cda0eb58…, 213 vlastných) so simulovane joined členom → vidí
--      214 riadkov (213 + 1), presne own + team.
--   4. Ten istý joined člen → stále vidí len svoj 1 riadok, NEvidí owner-a
--      (potvrdené jednosmerné správanie — member nevidí owner-a).
-- Testy 3 a 4 menili team_members.status len vnútri transakcie s ROLLBACK,
-- žiadna reálna dátová zmena neostala.
