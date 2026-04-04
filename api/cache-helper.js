const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  'https://qalcsmnvyuujsmnreglt.supabase.co',
  'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06'
);

async function getCache(key) {
  const { data } = await supabase
    .from('cache')
    .select('data')
    .eq('cache_key', key)
    .gt('expires_at', new Date().toISOString())
    .single();
  return data ? data.data : null;
}

async function setCache(key, value, hours = 24) {
  const expires = new Date(Date.now() + hours * 3600000).toISOString();
  await supabase.from('cache').upsert({
    cache_key: key,
    data: value,
    expires_at: expires
  }, { onConflict: 'cache_key' });
}

module.exports = { getCache, setCache };
