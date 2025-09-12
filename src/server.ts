import 'dotenv/config';
import fastify from "fastify";
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { supabase } from "./supabaseConnection.js";
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Resend } from 'resend';
import { z } from 'zod';

const app = fastify();

// ===================================================================
// CONFIGURAÇÃO DOS PLUGINS
// ===================================================================

// Regista o plugin do JWT com a chave secreta do Supabase
app.register(jwt, {
    secret: process.env.SUPABASE_JWT_SECRET!,
});

// Regista o plugin do CORS
app.register(cors, {
    origin: [
        "http://localhost:3000",
        "https://lock-front.onrender.com"
    ], 
    methods: ["GET", "POST", "PUT", "DELETE"],
});

// ===================================================================
// ROTAS
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
        const { data: exists } = await supabase.from("users").select("email").eq("email", email).single();
        if (exists) {
            return reply.status(400).send({ error: "Email já cadastrado" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert([{ name, email, password: hashedPassword }]).select().single();
        if (error) throw error;
        if (data) delete data.password;
        return { user: data };
    } catch (error) {
        console.error("Erro no registro:", error);
        return reply.status(500).send({ error: "Erro ao registrar usuário" });
    }
});

// --- ROTA DE LOGIN (COM GERAÇÃO DE TOKEN) ---
app.post("/login", async (request, reply) => {
    try {
        const { identifier, password } = request.body as { identifier: string; password: string };
        const { data: user, error } = await supabase.from("users").select("*").or(`email.eq.${identifier},name.eq.${identifier}`).single();
        if (error || !user) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        
        // CORRIGIDO: Gera o token JWT após o login
        const token = app.jwt.sign({ name: user.name, avatar_url: user.avatar_url }, { sub: user.id, expiresIn: '7 days' });

        delete user.password;
        
        // Retorna o utilizador E o token
        return { user, token };
    } catch (error) {
        console.error("Erro no login:", error);
        return reply.status(500).send({ error: "Erro no login" });
    }
});

// --- ROTA PARA ATUALIZAR O PERFIL (CORRIGIDA) ---
app.put('/profile/update', async (request, reply) => {
    try {
        // 1. Verifica o token JWT para saber quem é o utilizador
        await request.jwtVerify();
        const userId = request.user.sub;

        // 2. Valida os dados recebidos
        const updateProfileSchema = z.object({
            name: z.string().min(3).optional(),
            avatar_url: z.string().url().optional(),
        });
        const body = updateProfileSchema.parse(request.body);

        // 3. Monta o objeto de atualização
        const updateData: { name?: string; avatar_url?: string } = {};
        if (body.name) updateData.name = body.name;
        if (body.avatar_url) updateData.avatar_url = body.avatar_url;

        if (Object.keys(updateData).length === 0) {
            return reply.status(400).send({ message: 'Nenhum dado fornecido para atualização.' });
        }

        // 4. Atualiza os dados na tabela "users"
        const { data, error } = await supabase
            .from('users') // CORRIGIDO: de 'profiles' para 'users'
            .update(updateData)
            .eq('id', userId)
            .select()
            .single();

        if (error) throw error;
        
        if (data) delete data.password;

        return reply.status(200).send({ user: data });

    } catch (error) {
        console.error('Erro ao atualizar perfil:', error);
        if (error instanceof z.ZodError) {
            return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
        }
        return reply.status(500).send({ message: 'Erro interno ao atualizar perfil.' });
    }
});

// --- ROTA DE ESQUECI A PALAVRA-PASSE ---
app.post("/forgot-password", async (request, reply) => {
    // ... seu código de forgot-password (nenhuma alteração necessária) ...
});

// --- ROTA PARA REDEFINIR A PALAVRA-PASSE ---
app.post("/reset-password", async (request, reply) => {
    // ... seu código de reset-password (nenhuma alteração necessária) ...
});


// ===================================================================
// INICIALIZAÇÃO DO SERVIDOR
// ===================================================================
app.listen({
    host: "0.0.0.0",
    port: process.env.PORT ? Number(process.env.PORT) : 3333,
}).then(() => {
    console.log("🚀 Servidor a rodar com CORS ativado em http://localhost:3333");
});

