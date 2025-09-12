import 'dotenv/config';
import fastify from "fastify";
import cors from '@fastify/cors';
import { supabase } from "./supabaseConnection.js";
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Resend } from 'resend';
import jwt from '@fastify/jwt';
import { z } from 'zod';

const app = fastify();

// ===================================================================
// CONFIGURAÇÃO DOS PLUGINS
// ===================================================================

app.register(cors, {
    // Colocamos as URLs permitidas diretamente aqui
    origin: [
        "http://localhost:3000",             // Para o seu desenvolvimento local
        "https://lock-front.onrender.com"      // A URL exata do seu site no ar
    ], 
    methods: ["GET", "POST", "PUT", "DELETE"],
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
    // ... (nenhuma alteração aqui)
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
    // ... (nenhuma alteração aqui)
    try {
        const { identifier, password } = request.body as { identifier: string; password: string };

        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .or(`email.eq.${identifier},name.eq.${identifier}`)
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

// ===================================================================
// ROTA DE REDEFINIÇÃO DE SENHA (COM ENVIO DE E-MAIL)
// ===================================================================

app.post("/forgot-password", async (request, reply) => {
    try {
        const { email } = request.body as { email: string };
        
        // NOVO: Inicializa o Resend com a chave do seu arquivo .env
        const resend = new Resend(process.env.RESEND_API_KEY);

        const { data: user } = await supabase
            .from("users")
            .select("id")
            .eq("email", email)
            .single();

        if (!user) {
            return { message: "Se um usuário com este e-mail existir, um link de redefinição será enviado." };
        }

        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);

        await supabase
            .from("users")
            .update({ reset_token: hashedToken, reset_token_expires: expires.toISOString() })
            .eq("id", user.id);

        const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;
        
        // NOVO: Bloco que envia o e-mail de verdade
        await resend.emails.send({
            from: 'LOCK Platform <onboarding@resend.dev>',
            to: email,
            subject: 'Seu Link de Redefinição de Senha',
            html: `
              <h1>Redefinição de Senha</h1>
              <p>Você solicitou uma redefinição de senha. Clique no link abaixo para criar uma nova senha:</p>
              <a href="${resetUrl}" style="background-color: #00bfff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                Redefinir Senha
              </a>
              <p>Este link expira em 1 hora.</p>
            `,
        });

        return { message: "Se um usuário com este e-mail existir, um link de redefinição foi enviado." };

    } catch (error) {
        console.error("Erro em forgot-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

// --- ROTA PARA REDEFINIR A SENHA COM O TOKEN ---
app.post("/reset-password", async (request, reply) => {
    // ... (nenhuma alteração aqui)
    try {
        const { token, password } = request.body as { token: string; password: string };

        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        
        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .eq("reset_token", hashedToken)
            .single();

        if (error || !user || new Date(user.reset_token_expires) < new Date()) {
            return reply.status(400).send({ error: "Token inválido ou expirado." });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const { error: updateError } = await supabase
            .from("users")
            .update({
                password: hashedPassword,
                reset_token: null,
                reset_token_expires: null,
            })
            .eq("id", user.id);

        if (updateError) throw updateError;
        
        return { message: "Senha redefinida com sucesso! Você será redirecionado para o login." };

    } catch (error) {
        console.error("Erro em reset-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

// ROTA PARA ATUALIZAR O PERFIL DO USUÁRIO
app.put('/profile/update', async (request, reply) => {
  try {
    // 1. Validar o token JWT para pegar o ID do usuário
    await request.jwtVerify();
    const userId = request.user.sub; // 'sub' contém o ID do usuário

    // 2. Definir o esquema de validação para os dados recebidos
    const updateProfileSchema = z.object({
      name: z.string().min(3).optional(),
      avatar_url: z.string().url().optional(),
    });

    const body = updateProfileSchema.parse(request.body);

    // 3. Montar o objeto de atualização
    const updateData: { name?: string; avatar_url?: string } = {};
    if (body.name) updateData.name = body.name;
    if (body.avatar_url) updateData.avatar_url = body.avatar_url;

    // Se não há nada para atualizar, retorna erro
    if (Object.keys(updateData).length === 0) {
      return reply.status(400).send({ message: 'Nenhum dado fornecido para atualização.' });
    }

    // 4. Atualizar os dados no Supabase
    const { data, error } = await supabase
      .from('profiles')
      .update(updateData)
      .eq('id', userId)
      .select()
      .single();

    if (error) {
      throw error;
    }

    // 5. Retornar o perfil atualizado
    return reply.status(200).send({ user: data });

  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
    }
    return reply.status(500).send({ message: 'Erro interno ao atualizar perfil.' });
  }
});

// ... suas outras rotas e a inicialização do servidor ...
app.listen({
    host: "0.0.0.0",
    port: process.env.PORT ? Number(process.env.PORT) : 3333,
}).then(() => {
    console.log("🚀 Servidor rodando com CORS ativado em http://localhost:3333");
});