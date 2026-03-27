-- MailGuard: team_members table
-- Spusti v Supabase SQL Editor

CREATE TABLE IF NOT EXISTS public.team_members (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  member_email TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (owner_id, member_email)
);

-- Index pre rýchle vyhľadávanie podľa owner
CREATE INDEX IF NOT EXISTS team_members_owner_idx ON public.team_members(owner_id);

-- RLS: každý vlastník vidí len svoje záznamy
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner_select" ON public.team_members
  FOR SELECT USING (owner_id = auth.uid());

CREATE POLICY "owner_insert" ON public.team_members
  FOR INSERT WITH CHECK (owner_id = auth.uid());

CREATE POLICY "owner_delete" ON public.team_members
  FOR DELETE USING (owner_id = auth.uid());
