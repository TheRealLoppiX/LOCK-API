import 'dotenv/config';
import fastify from "fastify";
import cors from '@fastify/cors'; // Importe o cors
import { supabase } from "./supabaseConnection.js";
import bcrypt from 'bcrypt';

const app = fastify();

// ===================================================================
// CONFIGURAÇÃO DOS PLUGINS (DEVE VIR PRIMEIRO)
// ===================================================================

// Registre o plugin do CORS aqui, antes de todas as rotas
app.register(cors, {
    origin: "http://localhost:3000", // Permite requisições do seu frontend React
    methods: ["GET", "POST", "PUT", "DELETE"], // Métodos HTTP permitidos
});

// ===================================================================
// DEFINIÇÃO DE TIPOS E ROTAS
// ===================================================================

type Users = {
    name: string;
    email: string;
    password: string;
};

// --- ROTA DE CADASTRO (REGISTER) ---
app.post("/register", async (request, reply) => {
    try {
        const { name, email, password } = request.body as Users;

        const { data: exists } = await supabase
            .from("users")
            .select("email")
            .eq("email", email)
            .single();

        if (exists) {
            return reply.status(400).send({ error: "Email já cadastrado" });
        }

        // Lembrete sobre a segurança: use o bcrypt para hashear a senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const { data, error } = await supabase
            .from("users")
            .insert([{ name, email, password: hashedPassword }])
            .select()
            .single();

        if (error) throw error;

        if (data) {
            delete data.password;
        }

        return { user: data };
    } catch (error) {
        console.error("Erro no registro:", error);
        return reply.status(500).send({ error: "Erro ao registrar usuário" });
    }
});

// --- ROTA DE LOGIN ---
app.post("/login", async (request, reply) => {
    try {
        const { email, password } = request.body as { email: string; password: string };

        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .eq("email", email)
            .single();

        if (error || !user) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }

        delete user.password;
        return { user };
    } catch (error) {
        console.error("Erro no login:", error);
        return reply.status(500).send({ error: "Erro no login" });
    }
});


// --- ROTA GET PARA TESTE (OPCIONAL) ---
app.get("/users", async (request, reply) => {
    try {
        const { data: users, error } = await supabase.from("users").select("id, name, email");
        if (error) throw error;
        return { value: users };
    } catch (error) {
        console.error(error);
        return reply.status(500).send({ error: "Erro ao buscar usuários" });
    }
});

// ===================================================================
// INICIALIZAÇÃO DO SERVIDOR
// ===================================================================
app.listen({
    host: "0.0.0.0",
    port: process.env.PORT ? Number(process.env.PORT) : 3333,
}).then(() => {
    console.log("🚀 Servidor rodando com CORS ativado em http://localhost:3333");
});