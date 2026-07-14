import 'dotenv/config';
import fastify from "fastify";
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { supabase } from "./supabaseConnection.js";
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { Resend } from 'resend';
import { z } from 'zod';
import { aiService } from './services/AiService.js';

// bodyLimit maior que o padrão (1MB) para caber anexos de imagem/documento
// em base64 no chat da Aegis — o limite por arquivo é reforçado abaixo.
const app = fastify({ bodyLimit: 20 * 1024 * 1024 });

// ===================================================================
// ESQUEMAS DE VALIDAÇÃO (ZOD)
// ===================================================================
const registerUserSchema = z.object({ name: z.string().min(3), email: z.string().email(), password: z.string().min(6) });
const loginSchema = z.object({ identifier: z.string().min(3), password: z.string().min(6) });
const forgotPasswordSchema = z.object({ email: z.string().email() });
const resetPasswordSchema = z.object({ token: z.string().min(1), password: z.string().min(6) });
const updateProfileSchema = z.object({ name: z.string().min(3).optional(), avatar_url: z.string().url().optional() });
const createQuestionSchema = z.object({
  topic: z.string(),
  difficulty: z.string(),
  question: z.string().min(5),
  options: z.array(z.string()).length(4),
  correct_answer: z.string(),
  module_id: z.string().optional()
});
const createMaterialSchema = z.object({
  title: z.string().min(3),
  author: z.string().min(2),
  synopsis: z.string().optional(),
  type: z.enum(['Livro', 'Artigo', 'PDF', 'Apostila']), 
  cover_url: z.string().url(), 
  pdf_url: z.string().url(),   
  total_pages: z.coerce.number().optional(), 
});
const createModuleSchema = z.object({
  title: z.string().min(3),
  description: z.string().optional(),
  cover_url: z.string().url(),
  difficulty_level: z.coerce.number().min(1).max(5),
  duration_minutes: z.coerce.number().min(5).default(60)
});
// ===================================================================
// CONFIGURAÇÃO DOS PLUGINS
// ===================================================================
// Segredo dedicado só para os tokens da própria aplicação — não é o JWT
// secret do projeto Supabase (a app não usa Supabase Auth, então reusar
// aquele segredo não tinha propósito e ampliava o raio de um vazamento).
app.register(jwt, { secret: process.env.APP_JWT_SECRET! });
app.register(cors, {
  origin: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"]
});


// ===================================================================
// ROTAS
// ===================================================================

// ===================================================================
// ROTA DE HEALTH CHECKING
// ===================================================================
app.get('/ping', async (request, reply) => {
  return reply.send({ message: 'pong' });
});
/** @route POST /register */
app.post('/register', async (request, reply) => {
  try {
    const { name, email, password } = registerUserSchema.parse(request.body);

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert({
        name,
        email,
        password: hashedPassword,
        avatar_url: `https://api.dicebear.com/8.x/initials/svg?seed=${encodeURIComponent(name)}`
      })
      .select('id, name, email, avatar_url')
      .single();

    // ======================================================
    // ESTA É A MUDANÇA QUE VALIDA A DUPLICIDADE
    // ======================================================
    if (insertError) {
      // '23505' é o código de erro padrão do PostgreSQL para "unique_violation"
      if (insertError.code === '23505') {
        return reply.status(409).send({ message: "Este e-mail já está cadastrado." });
      }
      
      // Se for outro tipo de erro, loga e lança
      console.error("Erro ao inserir usuário no Supabase:", insertError);
      throw new Error("Falha ao criar usuário no banco de dados.");
    }
    // ======================================================

    if (!newUser) {
      throw new Error("Falha ao criar usuário, dados não retornados.");
    }

    const token = app.jwt.sign({
      sub: newUser.id.toString(),
      name: newUser.name,
      email: newUser.email,
      avatar_url: newUser.avatar_url,
    });

    return reply.status(201).send({ token });

  } catch (error: any) {
    // Se o erro for do Zod (validação)
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: "Dados inválidos.", details: error.issues });
    }
    // Pega qualquer outra mensagem de erro
    return reply.status(error.statusCode || 500).send({ message: error.message || "Erro interno do servidor" });
  }
});

/** @route POST /login */
app.post("/login", async (request, reply) => {
    try {
        const { identifier, password } = loginSchema.parse(request.body);
        const { data: user, error } = await supabase
            .from("users")
            .select("*")
            .or(`email.eq.${identifier},name.eq.${identifier}`)
            .maybeSingle();

        if (error) {
            console.error("❌ Erro no Supabase:", error); // LOG DE ERRO REAL
            return reply.status(500).send({ message: "Erro ao consultar banco de dados." });
        }

        if (!user) {
            console.log("⚠️ Usuário não encontrado:", identifier);
            return reply.status(401).send({ message: "Credenciais inválidas" });
        }

        // Verifica se a senha existe no banco (para usuários criados via OAuth/Google que não têm senha)
        if (!user.password) {
             return reply.status(401).send({ message: "Este usuário não possui senha configurada." });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            console.log("⚠️ Senha incorreta para:", identifier);
            return reply.status(401).send({ message: "Credenciais inválidas" });
        }

        // Gera token
        const token = app.jwt.sign({ 
            sub: user.id.toString(), 
            name: user.name, 
            email: user.email, 
            avatar_url: user.avatar_url,
            is_admin: user.is_admin || false
        }, { expiresIn: '7 days' });

        // Remove a senha antes de enviar pro front
        delete user.password;
        
        console.log("✅ Login Sucesso:", user.email);
        return { user, token };

    } catch (error) {
        if (error instanceof z.ZodError) { 
            return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() }); 
        }
        console.error("🔥 EXCEÇÃO CRÍTICA NO LOGIN:", error); 
        
        return reply.status(500).send({ message: "Erro interno no servidor ao tentar logar." });
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
app.get('/modules', async (request, reply) => {
  try {
    // Busca todos os módulos ordenados por data
    const { data: modules, error } = await supabase
      .from('exam_modules')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    return reply.send(modules);

  } catch (error) {
    console.error("Erro ao buscar módulos:", error);
    return reply.status(500).send({ message: "Erro ao carregar simulados." });
  }
});
app.get('/modules/:id/questions', async (request, reply) => {
  try {
    // Verifica Token (Necessário para saber QUEM é o usuário para bloquear)
    await request.jwtVerify();
    const user = request.user;
    const { id } = z.object({ id: z.string() }).parse(request.params);

    // ============================================================
    // 1. VERIFICAÇÃO DE "UMA VEZ POR DIA"
    // ============================================================
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Zera o horário para pegar o início do dia

    const { data: attempts, error: attemptError } = await supabase
      .from('user_exam_attempts')
      .select('id')
      .eq('user_id', user.sub)
      .eq('module_id', id)
      .gte('created_at', today.toISOString()); // Busca tentativas de hoje em diante

    if (attempts && attempts.length > 0) {
      return reply.status(429).send({ 
        message: "⛔ Você já realizou este simulado hoje. Tente novamente amanhã ou escolha outro módulo." 
      });
    }

    // ============================================================
    // 2. BUSCA DADOS DO MÓDULO (Incluindo duração)
    // ============================================================
    const { data: moduleData, error: moduleError } = await supabase
      .from('exam_modules')
      .select('*') // Vai trazer o duration_minutes
      .eq('id', id)
      .single();

    if (moduleError) return reply.status(404).send({ message: "Simulado não encontrado." });

    // 3. BUSCA AS QUESTÕES
    // NOTA: correct_answer_index NÃO é selecionado aqui de propósito — a
    // correção é feita no servidor, em POST /modules/:id/attempt, para que
    // o gabarito nunca seja enviado ao cliente antes da correção.
    const { data: questions, error: qError } = await supabase
      .from('questions')
      .select('id, question_text, options')
      .eq('module_id', id);

    if (qError) throw qError;

    return { module: moduleData, questions };

  } catch (error) {
    console.error("Erro ao buscar prova:", error);
    return reply.status(500).send({ message: "Erro interno." });
  }
});

// ===================================================================
// ROTA: SALVAR RESULTADO DO SIMULADO
// ===================================================================
app.post('/modules/:id/attempt', async (request, reply) => {
  try {
    await request.jwtVerify(); // Exige login

    const { id } = z.object({ id: z.string() }).parse(request.params);
    const { answers } = z.object({
      answers: z.record(z.string(), z.string())
    }).parse(request.body);

    // A nota é sempre calculada no servidor a partir do gabarito real —
    // nunca confiamos numa nota calculada pelo cliente.
    const { data: questions, error: qError } = await supabase
      .from('questions')
      .select('id, options, correct_answer_index')
      .eq('module_id', id);

    if (qError) throw qError;
    if (!questions || questions.length === 0) {
      return reply.status(404).send({ message: "Simulado não encontrado." });
    }

    let score = 0;
    for (const q of questions) {
      const correctOptionText = q.options[q.correct_answer_index];
      if (answers[q.id] === correctOptionText) score++;
    }

    const { error } = await supabase
      .from('user_exam_attempts')
      .insert({
        user_id: request.user.sub,
        module_id: id,
        score,
        total_questions: questions.length
      });

    if (error) throw error;

    return reply.status(201).send({ message: "Resultado salvo!", score, total_questions: questions.length });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
    }
    console.error("Erro ao salvar tentativa:", error);
    return reply.status(500).send({ message: "Erro ao salvar resultado." });
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

    // Inicia a query base
    let query = supabase.from('questions').select('*');

    // Apenas aplica o filtro de tópico se o tema NÃO for 'variado'
    if (topic !== 'variado') {
      query = query.eq('topic', topic);
    }
    
    // Se a dificuldade NÃO for um modo especial, filtra por ela
    if (difficulty && !['aleatório', 'temporizado', 'treinamento'].includes(difficulty)) {
      query = query.eq('difficulty', difficulty);
    }
    
    const { data: questions, error } = await query;
    if (error) throw error;

    if (!questions || questions.length === 0) {
      return reply.status(404).send({ message: 'Nenhuma pergunta encontrada.' });
    }

    // Embaralha e limita os resultados
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
/**
 * @route GET /library/all
 * @description Busca TODOS os dados da biblioteca para o usuário logado
 * chamando uma única função SQL segura.
 */
app.get('/library/all', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;

        // Chama a nossa nova super-função, passando o ID do usuário
        const { data, error } = await supabase.rpc('get_user_library_data', {
            p_user_id: userId
        });

        if (error) throw error;
        
        // A função já retorna o objeto JSON completo e formatado.
        // A gente só precisa enviá-lo de volta para o site.
        return data;

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

    } catch (error:any) {
        console.error('Erro ao atualizar status do material:', error);
        return reply.status(500).send({ 
            error: 'Erro ao atualizar status',
            details: error.message || error 
        });
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

/**
 * @route GET /profile/stats
 * @description Livros lidos e tentativas de simulado do usuário logado.
 * Substitui as consultas que o frontend fazia direto no Supabase com a
 * chave anônima (agora bloqueada por RLS em todas as tabelas).
 */
app.get('/profile/stats', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;

        const { data: readBooks, error: booksError } = await supabase
            .from('user_library')
            .select('book_id, book:books(title, cover_url)')
            .eq('user_id', userId)
            .eq('status', 'Lido');

        if (booksError) throw booksError;

        const { data: examAttempts, error: examsError } = await supabase
            .from('user_exam_attempts')
            .select('id, score, total_questions, completed_at, module:exam_modules(title, cover_url)')
            .eq('user_id', userId);

        if (examsError) throw examsError;

        return reply.send({ readBooks: readBooks || [], examAttempts: examAttempts || [] });
    } catch (error) {
        console.error('Erro ao buscar estatísticas de perfil:', error);
        return reply.status(500).send({ message: 'Erro ao buscar estatísticas de perfil.' });
    }
});

// =====================================================================
// ROTAS DE LIVROS (detalhe, progresso de leitura e avaliações)
// =====================================================================

app.get('/books/:id', async (request, reply) => {
    try {
        await request.jwtVerify();
        const { id } = z.object({ id: z.string().uuid() }).parse(request.params);

        const { data: book, error } = await supabase
            .from('books')
            .select('*')
            .eq('id', id)
            .single();

        if (error) return reply.status(404).send({ message: 'Material não encontrado.' });
        return reply.send(book);
    } catch (error) {
        if (error instanceof z.ZodError) return reply.status(400).send({ message: 'ID inválido.' });
        console.error('Erro ao buscar material:', error);
        return reply.status(500).send({ message: 'Erro ao buscar material.' });
    }
});

app.get('/books/:id/progress', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { id } = z.object({ id: z.string().uuid() }).parse(request.params);

        const { data: progress, error } = await supabase
            .from('reading_progress')
            .select('*')
            .eq('user_id', userId)
            .eq('book_id', id)
            .maybeSingle();

        if (error) throw error;
        return reply.send(progress || { current_page: 1, is_completed: false });
    } catch (error) {
        if (error instanceof z.ZodError) return reply.status(400).send({ message: 'ID inválido.' });
        console.error('Erro ao buscar progresso de leitura:', error);
        return reply.status(500).send({ message: 'Erro ao buscar progresso de leitura.' });
    }
});

const updateProgressSchema = z.object({
    current_page: z.number().int().nonnegative(),
    is_completed: z.boolean(),
});

app.put('/books/:id/progress', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { id } = z.object({ id: z.string().uuid() }).parse(request.params);
        const { current_page, is_completed } = updateProgressSchema.parse(request.body);

        const { error } = await supabase.from('reading_progress').upsert({
            user_id: userId,
            book_id: id,
            current_page,
            is_completed,
            last_read_at: new Date().toISOString(),
        }, { onConflict: 'user_id, book_id' });

        if (error) throw error;
        return reply.status(200).send({ message: 'Progresso salvo.' });
    } catch (error) {
        if (error instanceof z.ZodError) return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
        console.error('Erro ao salvar progresso de leitura:', error);
        return reply.status(500).send({ message: 'Erro ao salvar progresso de leitura.' });
    }
});

app.get('/books/:id/reviews', async (request, reply) => {
    try {
        await request.jwtVerify();
        const { id } = z.object({ id: z.string().uuid() }).parse(request.params);

        const { data: reviews, error } = await supabase
            .from('book_reviews')
            .select('*, users(name, avatar_url)')
            .eq('book_id', id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        return reply.send(reviews || []);
    } catch (error) {
        if (error instanceof z.ZodError) return reply.status(400).send({ message: 'ID inválido.' });
        console.error('Erro ao buscar avaliações:', error);
        return reply.status(500).send({ message: 'Erro ao buscar avaliações.' });
    }
});

const createReviewSchema = z.object({
    rating: z.number().int().min(1).max(5),
    comment: z.string().max(2000).optional().default(''),
});

app.post('/books/:id/reviews', async (request, reply) => {
    try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { id } = z.object({ id: z.string().uuid() }).parse(request.params);
        const { rating, comment } = createReviewSchema.parse(request.body);

        const { error } = await supabase.from('book_reviews').insert({
            user_id: userId,
            book_id: id,
            rating,
            comment,
        });

        if (error) throw error;
        return reply.status(201).send({ message: 'Avaliação enviada!' });
    } catch (error) {
        if (error instanceof z.ZodError) return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
        console.error('Erro ao enviar avaliação:', error);
        return reply.status(500).send({ message: 'Erro ao enviar avaliação.' });
    }
});

// =====================================================================
// ROTAS DOS LABORATÓRIOS
// =====================================================================

// --- SQL INJECTION ---
app.post('/labs/sql-injection/1', async (request, reply) => {
  const { username, password } = request.body as any;

  // Lógica de Sucesso: Verifica a presença de uma aspa simples
  if (username?.includes("'") || password?.includes("'")) {
    // Retorna um status 500, mas com uma mensagem de sucesso no corpo
    // para o frontend interpretar como a conclusão do laboratório.
    return reply.status(500).send({
      success: true,
      message: 'Internal Server Error: Erro na sintaxe da sua consulta SQL. O banco de dados parece ser vulnerável.'
    });
  }

  // Mensagem de Falha Padrão para qualquer outra entrada
  return reply.status(401).send({
    success: false,
    message: 'Usuário ou senha inválidos.'
  });
});
app.post('/labs/sql-injection/2', async (request, reply) => { // Nível 2
  const { username, password } = request.body as any;
  if (username === `administrator'--`) {
    return reply.send({ success: true, message: 'Autenticação bypassada com sucesso! Redirecionando para o painel de controle...' });
  }
  return reply.status(401).send({ success: false, message: 'Credenciais incorretas.' });
});

app.post('/labs/sql-injection/3', async (request, reply) => { // Nível 3
  const { username, password } = request.body as any;
  const unionPayload = `' UNION SELECT 'Sup3r_S3cr3t_P4ss', NULL --`;
  if (username.toLowerCase().includes(unionPayload.toLowerCase())) {
    return reply.send({ success: true, message: 'Login bem-sucedido! Bem-vindo de volta, Sup3r_S3cr3t_P4ss.' });
  }
  return reply.status(401).send({ success: false, message: 'Usuário não encontrado.' });
});

// --- BRUTE FORCE ---
app.post('/labs/brute-force/1', async (request, reply) => { // Nível 1
  const validUsers = ['admin', 'guest'];
  const { username } = request.body as any;
  if (validUsers.includes(username)) {
    return reply.status(401).send({ success: false, message: 'Senha incorreta.' }); // "Sucesso" para o pentester
  }
  return reply.status(401).send({ success: false, message: 'Usuário não encontrado.' });
});

// --- Nível 2 ---
// Função auxiliar para gerar a senha aleatória
const generateRandomPassword = () => {
  return Math.random().toString(36).slice(-8); // Gera 8 caracteres alfanuméricos
};

// ROTA 1: Iniciar o laboratório
app.post('/labs/brute-force/2/start', async (request, reply) => {
  const password = generateRandomPassword();
  
  // A CORREÇÃO ESTÁ AQUI:
  // A diretiva // @ts-ignore diz ao TypeScript para ignorar o erro de tipo na próxima linha.
  // É a forma correta de lidar com exceções intencionais como esta.
  // @ts-ignore 
  const labToken = await reply.jwtSign({ password }, { expiresIn: '15m' });

  return { labToken };
});
// ROTA 2: Verificar a tentativa de senha
app.post('/labs/brute-force/2', async (request, reply) => {
  try {
    const { passwordGuess, labToken } = request.body as any;

    if (!labToken) {
      return reply.status(400).send({ success: false, message: "Token do laboratório não fornecido." });
    }

    // O servidor verifica o token e extrai a senha correta de dentro dele
    const decodedToken = app.jwt.verify(labToken) as { password: string };
    const correctPassword = decodedToken.password;

    if (passwordGuess === correctPassword) {
      return reply.send({ success: true, message: `Acesso concedido! Senha "${correctPassword}" encontrada.` });
    } else {
      return reply.status(401).send({ success: false, message: 'Senha incorreta.' });
    }
  } catch (error) {
    return reply.status(401).send({ success: false, message: "Token do laboratório inválido ou expirado. Recarregue a página." });
  }
});

const bruteForceTracker: { [ip: string]: { attempts: number, lockUntil: number | null } } = {};
app.post('/labs/brute-force/3', async (request, reply) => { // Nível 3
  const ip = request.ip;
  if (!bruteForceTracker[ip]) {
    bruteForceTracker[ip] = { attempts: 0, lockUntil: null };
  }
  const tracker = bruteForceTracker[ip];

  if (tracker.lockUntil && Date.now() < tracker.lockUntil) {
    const timeLeft = Math.ceil((tracker.lockUntil - Date.now()) / 1000);
    return reply.status(429).send({ success: false, message: `Muitas tentativas falhas. Tente novamente em ${timeLeft} segundos.` });
  }
  tracker.lockUntil = null;
  
  const { password } = request.body as any;
  if (password === '4815') {
    tracker.attempts = 0;
    return reply.send({ success: true, message: 'Acesso concedido! Proteção de rate limit contornada.' });
  } else {
    tracker.attempts++;
    if (tracker.attempts >= 3) {
      tracker.lockUntil = Date.now() + 60000;
      tracker.attempts = 0;
      return reply.status(429).send({ success: false, message: `Muitas tentativas falhas. Tente novamente em 60 segundos.` });
    }
    return reply.status(401).send({ success: false, message: 'Credenciais incorretas.' });
  }
});

/**
 * @route POST /admin/questions/generate
 * @description Gera rascunhos de questões com a Aegis para o admin revisar
 * e cadastrar manualmente via POST /admin/questions — nada é salvo aqui.
 */
app.post('/admin/questions/generate', async (request, reply) => {
  try {
    await request.jwtVerify();
    if (!request.user.is_admin) {
      return reply.status(403).send({ message: "Acesso negado." });
    }

    const { tema, quantidade } = z.object({
      tema: z.string().min(2).max(100),
      quantidade: z.coerce.number().int().min(1).max(10),
    }).parse(request.body);

    const questoes = await aiService.gerarQuestoesIA(tema, quantidade);
    return reply.send({ questoes });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: 'Dados inválidos.', issues: error.format() });
    }
    console.error("Erro ao gerar questões com IA:", error);
    return reply.status(500).send({ message: "Erro ao gerar questões com IA." });
  }
});

app.post('/admin/questions', async (request, reply) => {
  try {
    await request.jwtVerify();
    const user = request.user;

    if (!user.is_admin) {
      return reply.status(403).send({ message: "Acesso negado." });
    }

    const body = createQuestionSchema.parse(request.body);

    const correctIndex = body.options.indexOf(body.correct_answer);

    if (correctIndex === -1) {
      return reply.status(400).send({ message: "A resposta correta não foi encontrada entre as opções." });
    }

    const { error } = await supabase
      .from('questions')
      .insert({
        topic: body.topic,
        difficulty: body.difficulty,
        question_text: body.question, 
        options: body.options,
        correct_answer_index: correctIndex, 
        module_id: body.module_id || null
      });

    if (error) throw error;

    return reply.status(201).send({ message: "Questão cadastrada com sucesso!" });

  } catch (error) {
    console.error("Erro ao cadastrar:", error);
    return reply.status(500).send({ message: "Erro ao salvar questão." });
  }
});

app.post('/admin/materials', async (request, reply) => {
  try {
    // 1. Segurança: Verifica Token e se é Admin
    await request.jwtVerify();
    const user = request.user;

    if (!user.is_admin) {
      return reply.status(403).send({ message: "⛔ Acesso negado. Apenas administradores." });
    }

    // 2. Validação dos dados
    const body = createMaterialSchema.parse(request.body);

    // 3. Inserção no Supabase
    const { error } = await supabase
      .from('books')
      .insert({
        title: body.title,
        author: body.author,
        synopsis: body.synopsis,
        type: body.type,
        cover_url: body.cover_url,
        pdf_url: body.pdf_url, 
        total_pages: body.total_pages || 0
      });

    if (error) throw error;

    return reply.status(201).send({ message: "📚 Material cadastrado com sucesso!" });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: "Dados inválidos.", issues: error.format() });
    }
    console.error("Erro ao cadastrar material:", error);
    return reply.status(500).send({ message: "Erro interno ao salvar material." });
  }
});
app.post('/admin/modules', async (request, reply) => {
  try {
    // A. Segurança: Verifica Token e se é Admin
    await request.jwtVerify();
    const user = request.user;

    if (!user.is_admin) {
      return reply.status(403).send({ message: "⛔ Acesso negado. Apenas administradores." });
    }

    // B. Validação dos dados recebidos
    const body = createModuleSchema.parse(request.body);

    // C. Inserção no Supabase (Tabela exam_modules)
    const { error } = await supabase
      .from('exam_modules')
      .insert({
        title: body.title,
        description: body.description,
        cover_url: body.cover_url,
        difficulty_level: body.difficulty_level,
        duration_minutes: body.duration_minutes
      });

    if (error) throw error;

    return reply.status(201).send({ message: "🏆 Módulo de Simulado criado com sucesso!" });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: "Dados inválidos.", issues: error.format() });
    }
    console.error("Erro ao criar módulo:", error);
    return reply.status(500).send({ message: "Erro interno ao salvar módulo." });
  }
});
// --- XSS ---
// (XSS Nível 1 é Frontend-Puro, não precisa de rota)

// Simulação de "banco de dados" de comentários para os labs de XSS
const xssCommentsDb: { author: string, site: string, comment: string }[] = [];
const xssCommentsDbFiltered: { author: string, site: string, comment: string }[] = [];

app.post('/labs/xss/2', async (request, reply) => { // Nível 2 - Salvar comentário
  const { author, site, comment } = request.body as any;
  xssCommentsDb.push({ author, site, comment });
  return reply.send({ success: true });
});
app.get('/labs/xss/2/comments', async (request, reply) => { // Nível 2 - Buscar comentários
  return reply.send(xssCommentsDb);
});

app.post('/labs/xss/3', async (request, reply) => { // Nível 3 - Salvar comentário com filtro
  let { author, site, comment } = request.body as any;
  // Filtro ingênuo
  site = site.replace(/alert/gi, "").replace(/<script>/gi, "");
  xssCommentsDbFiltered.push({ author, site, comment });
  return reply.send({ success: true });
});
app.get('/labs/xss/3/comments', async (request, reply) => { // Nível 3 - Buscar comentários filtrados
  return reply.send(xssCommentsDbFiltered);
});

// ===================================================================
// ROTAS DA IA (AEGIS)
// ===================================================================

/**
 * @route POST /ai/chat
 * @description Envia uma mensagem para a Aegis e recebe a resposta.
 */
const ALLOWED_ATTACHMENT_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'application/pdf', 'text/plain'];
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5MB por arquivo, antes do base64

const attachmentSchema = z.object({
  name: z.string().min(1).max(200),
  mimeType: z.enum(ALLOWED_ATTACHMENT_TYPES as [string, ...string[]]),
  data: z.string().min(1),
}).refine((att) => Buffer.byteLength(att.data, 'base64') <= MAX_ATTACHMENT_BYTES, {
  message: 'Arquivo maior que o limite de 5MB.',
});

const chatSchema = z.object({
  message: z.string().max(2000).default(''),
  attachments: z.array(attachmentSchema).max(3).optional(),
}).refine((body) => body.message.trim().length > 0 || (body.attachments && body.attachments.length > 0), {
  message: 'Envie uma mensagem ou pelo menos um anexo.',
});

app.post('/ai/chat', async (request, reply) => {
  try {
    await request.jwtVerify();
    const { message, attachments } = chatSchema.parse(request.body);

    const response = await aiService.askAegis(message, 800, attachments);
    return reply.send({ response });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: 'Mensagem inválida.', issues: error.format() });
    }
    console.error('Erro na rota /ai/chat:', error);
    return reply.status(500).send({ message: 'Erro ao processar com IA.' });
  }
});

/**
 * @route POST /ai/analyze-quiz
 * @description Recebe questões que o usuário errou e retorna análise da Aegis.
 */
app.post('/ai/analyze-quiz', async (request, reply) => {
  try {
    await request.jwtVerify();
    const { wrongQuestions } = z.object({
      wrongQuestions: z.array(z.string().min(1)).min(1).max(20)
    }).parse(request.body);

    const analysis = await aiService.analisarErros(wrongQuestions);
    return reply.send({ analysis });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.status(400).send({ message: 'Dados inválidos.' });
    }
    console.error('Erro na rota /ai/analyze-quiz:', error);
    return reply.status(500).send({ message: 'Erro ao analisar resultados.' });
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

