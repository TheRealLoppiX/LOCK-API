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

app.register(jwt, {
    secret: process.env.SUPABASE_JWT_SECRET!,
});

app.register(cors, {
    origin: ["http://localhost:3000", "https://lock-front.onrender.com"], 
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
        
        const token = app.jwt.sign(
            { 
                sub: user.id.toString(), // CORRIGIDO: Converte o ID (número) para string
                name: user.name,
                avatar_url: user.avatar_url,
            }, 
            {
                expiresIn: '7 days',
            }
        );

        delete user.password;
        
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

app.post("/forgot-password", async (request, reply) => {
    try {
        const { email } = request.body as { email: string };
        const { data: user } = await supabase.from("users").select("id").eq("email", email).single();
        if (!user) {
            return { message: "Se um utilizador com este e-mail existir, um link de redefinição será enviado." };
        }
        
        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);

        await supabase.from("users").update({ reset_token: hashedToken, reset_token_expires: expires.toISOString() }).eq("id", user.id);
        
        const resetUrl = `https://lock-front.onrender.com/reset-password/${resetToken}`;
        const resend = new Resend(process.env.RESEND_API_KEY);
        
        await resend.emails.send({
            from: 'LOCK Platform <onboarding@resend.dev>',
            to: email,
            subject: 'O seu Link de Redefinição de Palavra-passe',
            html: `<p>Clique aqui para redefinir a sua palavra-passe: <a href="${resetUrl}">Redefinir Palavra-passe</a>. Este link expira em 1 hora.</p>`,
        });

        return { message: "Se um utilizador com este e-mail existir, um link de redefinição foi enviado." };
    } catch (error) {
        console.error("Erro em forgot-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

// --- ROTA PARA REDEFINIR A SENHA COM O TOKEN ---
app.post("/reset-password", async (request, reply) => {
    try {
        const { token, password } = request.body as { token: string; password: string };
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        
        const { data: user, error } = await supabase.from("users").select("*").eq("reset_token", hashedToken).single();
        
        if (error || !user || new Date(user.reset_token_expires) < new Date()) {
            return reply.status(400).send({ error: "Token inválido ou expirado." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await supabase.from("users").update({ password: hashedPassword, reset_token: null, reset_token_expires: null }).eq("id", user.id);
        
        return { message: "Palavra-passe redefinida com sucesso!" };
    } catch (error) {
        console.error("Erro em reset-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
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

