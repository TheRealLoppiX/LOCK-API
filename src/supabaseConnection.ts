import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const supaBaseURL = process.env.SUPABASEURL || 'https://grcxqjrodvulxnhtrqhq.supabase.co'
const supaBaseKEY = process.env.SUPABASEKEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdyY3hxanJvZHZ1bHhuaHRycWhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY3MzgyMjMsImV4cCI6MjA3MjMxNDIyM30.8VGjs7HtQ32ZLvGPV8MZTIiftucZmlW0rw9jlYQzraw'

const supabase = createClient(supaBaseURL, supaBaseKEY, {
    auth: {
        persistSession: false
    }
})



export { supabase  }