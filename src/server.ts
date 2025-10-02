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
// ROTAS
// ===================================================================

/** @route POST /register */
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

/** @route POST /login */
app.post("/login", async (request, reply) => {
    try {
        const { identifier, password } = loginSchema.parse(request.body);
        const { data: user, error } = await supabase.from("users").select("*").or(`email.eq.${identifier},name.eq.${identifier}`).single();
        if (error || !user || !user.id) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return reply.status(401).send({ error: "Credenciais inválidas" });
        }
        const token = app.jwt.sign({ sub: user.id.toString(), name: user.name, avatar_url: user.avatar_url }, { expiresIn: '7 days' });
        delete user.password;
        return { user, token };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro no login:", error);
        return reply.status(500).send({ error: "Erro no login" });
    }
});

/** @route PUT /profile/update */
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
 * @description Inicia o fluxo de redefinição de palavra-passe.
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
                subject: 'O seu Link de Redefinição de Palavra-passe',
                html: `<p>Clique aqui para redefinir: <a href="${resetUrl}">Redefinir Palavra-passe</a>.</p>`,
            });
        }
        return { message: "Se um utilizador com este e-mail existir, um link de redefinição foi enviado." };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro em forgot-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

/**
 * @route POST /reset-password
 * @description Conclui a redefinição de palavra-passe.
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
        return { message: "Palavra-passe redefinida com sucesso!" };
    } catch (error) {
        if (error instanceof z.ZodError) { return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); }
        console.error("Erro em reset-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
    }
});

// ===================================================================
// ROTA DO QUIZ
// ===================================================================

const getQuizQuestionsSchema = z.object({
  topic: z.string(),
  difficulty: z.enum(['fácil', 'médio', 'difícil', 'aleatório', 'temporizado', 'treinamento']),
  limit: z.coerce.number().int().positive().optional().default(10),
});

app.get('/quiz/questions', async (request, reply) => {
  try {
    await request.jwtVerify(); // Protege a rota
    const { topic, difficulty, limit } = getQuizQuestionsSchema.parse(request.query);

    let query = supabase.from('questions').select('*').eq('topic', topic);

    // Se a dificuldade NÃO for um modo especial, filtra por ela
    if (difficulty && !['aleatório', 'temporizado', 'treinamento'].includes(difficulty)) {
      query = query.eq('difficulty', difficulty);
    }
    
    const { data: questions, error } = await query;
    if (error) throw error;

    if (!questions || questions.length === 0) {
      return reply.status(404).send({ message: 'Nenhuma pergunta encontrada.' });
    }

    const shuffled = questions.sort(() => 0.5 - Math.random());
    const selectedQuestions = shuffled.slice(0, limit);

    return reply.send(selectedQuestions);
  } catch (error) {
    console.error("Erro ao buscar perguntas do quiz:", error);
    return reply.status(500).send({ error: "Erro ao buscar perguntas" });
  }
});

// ===================================================================
// ROTAS DA BIBLIOTECA
// ===================================================================

/**
 * @route GET /library/all
 * @description Busca TODOS os materiais de estudo e o status de cada um
 * PARA O USUÁRIO LOGADO. Também busca o último material
 * acessado pelo usuário.
 */
app.get('/library/all', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;

        // 1. Busca todos os materiais da tabela 'materials'
        const { data: allMaterials, error: materialsError } = await supabase
            .from('materials')
            .select('*');
        if (materialsError) throw materialsError;

        // 2. Busca os status que ESTE usuário salvou
        const { data: userStatuses, error: statusesError } = await supabase
            .from('user_materials_status')
            .select('material_id, status')
            .eq('user_id', userId);
        if (statusesError) throw statusesError;

        // 3. Busca o último material acessado por ESTE usuário
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('last_accessed_material_id')
            .eq('id', userId)
            .single();
        if (userError) throw userError;

        // Combina os status com a lista de todos os materiais
        const materialsWithStatus = allMaterials.map(material => {
            const userStatus = userStatuses.find(s => s.material_id === material.id);
            return {
                ...material,
                status: userStatus ? userStatus.status : null // Adiciona o status ou null
            };
        });

        return {
            allMaterials: materialsWithStatus,
            lastAccessedId: userData.last_accessed_material_id
        };
    } catch (error) {
        console.error('Erro ao buscar dados da biblioteca:', error);
        return reply.status(500).send({ error: 'Erro ao buscar dados da biblioteca' });
    }
});


/**
 * @route PUT /library/status
 * @description Atualiza ou insere o status de um material para o usuário.
 * Ex: Mover um livro para a estante "Lendo".
 */
app.put('/library/status', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { materialId, status } = z.object({
            materialId: z.string().uuid(),
            status: z.string()
        }).parse(request.body);

        // AGORA, em vez de 'upsert', chamamos nossa função especial via 'rpc'
        const { error } = await supabase.rpc('update_user_material_status', {
            p_user_id: userId,
            p_material_id: materialId,
            p_status: status
        });

        if (error) throw error; // Se a função der erro, ele será capturado aqui

        return reply.status(200).send({ message: 'Status atualizado com sucesso' });

    } catch (error) {
        console.error('Erro ao atualizar status do material:', error);
        return reply.status(500).send({ error: 'Erro ao atualizar status do material' });
    }
});

/**
 * @route PUT /library/last-accessed/:materialId
 * @description Salva o ID do último material que o usuário clicou.
 * É a base para a funcionalidade "Continue estudando".
 */
app.put('/library/last-accessed/:materialId', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { materialId } = z.object({ materialId: z.string().uuid() }).parse(request.params);

        const { error } = await supabase
            .from('users')
            .update({ last_accessed_material_id: materialId })
            .eq('id', userId);

        if (error) throw error;
        
        return reply.status(200).send({ message: 'Último material acessado salvo com sucesso' });

    } catch (error) {
        console.error('Erro ao salvar último material acessado:', error);
        return reply.status(500).send({ error: 'Erro ao salvar último material acessado' });
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

