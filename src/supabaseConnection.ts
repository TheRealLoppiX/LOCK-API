import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const supaBaseURL = process.env.SUPABASE_URL || '';
const supaBaseKEY = process.env.SUPABASE_KEY || '';

const supabase = createClient(supaBaseURL, supaBaseKEY, {
    auth: {
        persistSession: false
    }
})



export { supabase  }