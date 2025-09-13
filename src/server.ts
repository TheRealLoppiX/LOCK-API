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
// ESQUEMAS DE VALIDAÇÃO (ZOD)
// ===================================================================
const registerUserSchema = z.object({ name: z.string().min(3), email: z.string().email(), password: z.string().min(6) });
const loginSchema = z.object({ identifier: z.string().min(3), password: z.string().min(6) });
const forgotPasswordSchema = z.object({ email: z.string().email() });
const resetPasswordSchema = z.object({ token: z.string().min(1), password: z.string().min(6) });
const updateProfileSchema = z.object({ name: z.string().min(3).optional(), avatar_url: z.string().url().optional() });

// ===================================================================
// CONFIGURAÇÃO DOS PLUGINS
// ===================================================================
app.register(jwt, { secret: process.env.SUPABASE_JWT_SECRET! });
app.register(cors, { origin: ["http://localhost:3000", "https://lock-front.onrender.com"], methods: ["GET", "POST", "PUT", "DELETE"] });

// ===================================================================
// ROTAS DE AUTENTICAÇÃO E PERFIL
// ===================================================================

/**
 * @route POST /register
 * @description Registra um novo usuário.
 */
app.post("/register", async (request, reply) => {
    try {
        const { name, email, password } = registerUserSchema.parse(request.body);
        const { data: exists } = await supabase.from("users").select("email").eq("email", email).single();
        if (exists) { return reply.status(409).send({ error: "Email já cadastrado" }); }
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from("users").insert([{ name, email, password: hashedPassword }]).select().single();
        if (error) throw error;
        if (data) delete data.password;
        return reply.status(201).send({ user: data });
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro no registro:", error);
        return reply.status(500).send({ error: "Erro ao registrar usuário" });
    }
});

/**
 * @route POST /login
 * @description Autentica um usuário e retorna um token JWT.
 */
app.post("/login", async (request, reply) => {
    try {
        const { identifier, password } = loginSchema.parse(request.body);
        const { data: user, error } = await supabase.from("users").select("*").or(`email.eq.${identifier},name.eq.${identifier}`).single();
        
        // CORRIGIDO: Adicionada uma verificação extra para garantir que o 'user' e 'user.id' existem
        if (error || !user || !user.id) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        
        const token = app.jwt.sign(
            { 
                sub: user.id.toString(),
                name: user.name,
                avatar_url: user.avatar_url 
            }, 
            { expiresIn: '7 days' }
        );

        delete user.password;
        return { user, token };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro no login:", error);
        return reply.status(500).send({ error: "Erro no login" });
    }
});

/**
 * @route PUT /profile/update
 * @description Atualiza o perfil de um usuário autenticado.
 */
app.put('/profile/update', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const body = updateProfileSchema.parse(request.body);
        if (Object.keys(body).length === 0) {
            return reply.status(400).send({ message: 'Nenhum dado fornecido para atualização.' });
        }
        const { data, error } = await supabase.from('users').update(body).eq('id', userId).select().single();
        if (error) throw error;
        if (data) delete data.password;
        return reply.status(200).send({ user: data });
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error('Erro ao atualizar perfil:', error);
        return reply.status(500).send({ message: 'Erro interno ao atualizar perfil.' });
    }
});

/**
 * @route POST /forgot-password
 * @description Inicia o fluxo de redefinição de senha.
 */
app.post("/forgot-password", async (request, reply) => {
    try {
        const { email } = forgotPasswordSchema.parse(request.body);
        const { data: user } = await supabase.from("users").select("id").eq("email", email).single();
        if (user) {
            const resetToken = crypto.randomBytes(32).toString("hex");
            const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
            const expires = new Date(Date.now() + 3600000); // 1 hora
            await supabase.from("users").update({ reset_token: hashedToken, reset_token_expires: expires.toISOString() }).eq("id", user.id);
            const resetUrl = `https://lock-front.onrender.com/reset-password/${resetToken}`;
            const resend = new Resend(process.env.RESEND_API_KEY);
            await resend.emails.send({
                from: 'LOCK Platform <onboarding@resend.dev>',
                to: email,
                subject: 'Seu Link de Redefinição de Senha',
                html: `<p>Clique aqui para redefinir: <a href="${resetUrl}">Redefinir Senha</a>.</p>`,
            });
        }
        return { message: "Se um usuário com este e-mail existir, um link de redefinição foi enviado." };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro em forgot-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

/**
 * @route POST /reset-password
 * @description Conclui a redefinição de senha.
 */
app.post("/reset-password", async (request, reply) => {
    try {
        const { token, password } = resetPasswordSchema.parse(request.body);
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        const { data: user, error } = await supabase.from("users").select("*").eq("reset_token", hashedToken).single();
        if (error || !user || new Date(user.reset_token_expires) < new Date()) {
            return reply.status(400).send({ error: "Token inválido ou expirado." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await supabase.from("users").update({ password: hashedPassword, reset_token: null, reset_token_expires: null }).eq("id", user.id);
        return { message: "Senha redefinida com sucesso!" };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro em reset-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

/**
 * @route GET /labs/completions
 * @description Obtém os laboratórios concluídos pelo usuário.
 */
app.get('/labs/completions', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { data, error } = await supabase.from('lab_completions').select('lab_id').eq('user_id', userId);
        if (error) throw error;
        const completedIds = data.map(completion => completion.lab_id);
        return completedIds;
    } catch (error) {
        console.error('Erro ao obter conclusões de laboratórios:', error);
        return reply.status(500).send({ message: 'Erro ao obter progresso.' });
    }
});

/**
 * @route POST /labs/complete
 * @description Marca um laboratório como concluído.
 */
app.post('/labs/complete', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { labId } = z.object({ labId: z.string() }).parse(request.body);
        
        // CORRIGIDO: Usa .maybeSingle() para não dar erro se não encontrar nada.
        const { data: existing, error: selectError } = await supabase.from('lab_completions').select('id').eq('user_id', userId).eq('lab_id', labId).maybeSingle();
        if (selectError) throw selectError;

        if (existing) {
            return { message: 'Laboratório já concluído.' };
        }
        const { error: insertError } = await supabase.from('lab_completions').insert({ user_id: userId, lab_id: labId });
        if (insertError) throw insertError;

        return reply.status(201).send({ message: 'Progresso guardado com sucesso!' });
    } catch (error) {
        console.error('Erro ao marcar laboratório como concluído:', error);
        return reply.status(500).send({ message: 'Erro ao guardar progresso.' });
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