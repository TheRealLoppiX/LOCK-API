import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const supaBaseURL = process.env.SUPABASE_URL || '';
// O backend usa a service_role key, não a anon key: todas as tabelas têm
// RLS travado para o público, e é este processo (já autenticado via JWT
// próprio + checagens de dono/admin) que decide o que cada usuário pode
// ver ou alterar. NUNCA expor esta chave ao frontend.
const supaBaseKEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const supabase = createClient(supaBaseURL, supaBaseKEY, {
    auth: {
        persistSession: false
    }
})



export { supabase  }