var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// src/supabaseConnection.ts
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
var supaBaseURL, supaBaseKEY, supabase;
var init_supabaseConnection = __esm({
  "src/supabaseConnection.ts"() {
    "use strict";
    dotenv.config();
    supaBaseURL = process.env.SUPABASEURL || "https://grcxqjrodvulxnhtrqhq.supabase.co";
    supaBaseKEY = process.env.SUPABASEKEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdyY3hxanJvZHZ1bHhuaHRycWhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY3MzgyMjMsImV4cCI6MjA3MjMxNDIyM30.8VGjs7HtQ32ZLvGPV8MZTIiftucZmlW0rw9jlYQzraw";
    supabase = createClient(supaBaseURL, supaBaseKEY, {
      auth: {
        persistSession: false
      }
    });
  }
});

// src/server.ts
import "dotenv/config";
import fastify from "fastify";
import cors from "@fastify/cors";
import jwt from "@fastify/jwt";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { Resend } from "resend";
import { z } from "zod";
var require_server = __commonJS({
  "src/server.ts"() {
    init_supabaseConnection();
    var app = fastify();
    var registerUserSchema = z.object({ name: z.string().min(3), email: z.string().email(), password: z.string().min(6) });
    var loginSchema = z.object({ identifier: z.string().min(3), password: z.string().min(6) });
    var forgotPasswordSchema = z.object({ email: z.string().email() });
    var resetPasswordSchema = z.object({ token: z.string().min(1), password: z.string().min(6) });
    var updateProfileSchema = z.object({ name: z.string().min(3).optional(), avatar_url: z.string().url().optional() });
    var createQuestionSchema = z.object({
      topic: z.string(),
      difficulty: z.string(),
      question: z.string().min(5),
      options: z.array(z.string()).length(4),
      correct_answer: z.string(),
      module_id: z.string().optional()
    });
    var createMaterialSchema = z.object({
      title: z.string().min(3),
      author: z.string().min(2),
      synopsis: z.string().optional(),
      type: z.enum(["Livro", "Artigo", "PDF", "Apostila"]),
      // Tipos permitidos
      cover_url: z.string().url(),
      // Tem que ser um link válido
      pdf_url: z.string().url(),
      // Tem que ser um link válido
      total_pages: z.coerce.number().optional()
      // Converte string pra number se vier do form
    });
    var createModuleSchema = z.object({
      title: z.string().min(3, "O t\xEDtulo deve ter pelo menos 3 caracteres"),
      description: z.string().optional(),
      cover_url: z.string().url("A URL da imagem deve ser v\xE1lida"),
      difficulty_level: z.coerce.number().min(1).max(5).default(1)
    });
    app.register(jwt, { secret: process.env.SUPABASE_JWT_SECRET });
    app.register(cors, {
      origin: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      credentials: true,
      allowedHeaders: ["Content-Type", "Authorization"]
    });
    app.get("/ping", async (request, reply) => {
      return reply.send({ message: "pong" });
    });
    app.post("/register", async (request, reply) => {
      try {
        const { name, email, password } = registerUserSchema.parse(request.body);
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data: newUser, error: insertError } = await supabase.from("users").insert({
          name,
          email,
          password: hashedPassword,
          avatar_url: `https://api.dicebear.com/8.x/initials/svg?seed=${encodeURIComponent(name)}`
        }).select("id, name, email, avatar_url").single();
        if (insertError) {
          if (insertError.code === "23505") {
            return reply.status(409).send({ message: "Este e-mail j\xE1 est\xE1 cadastrado." });
          }
          console.error("Erro ao inserir usu\xE1rio no Supabase:", insertError);
          throw new Error("Falha ao criar usu\xE1rio no banco de dados.");
        }
        if (!newUser) {
          throw new Error("Falha ao criar usu\xE1rio, dados n\xE3o retornados.");
        }
        const token = app.jwt.sign({
          sub: newUser.id.toString(),
          name: newUser.name,
          email: newUser.email,
          avatar_url: newUser.avatar_url
        });
        return reply.status(201).send({ token });
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", details: error.issues });
        }
        return reply.status(error.statusCode || 500).send({ message: error.message || "Erro interno do servidor" });
      }
    });
    app.post("/login", async (request, reply) => {
      console.log("\u{1F4E5} Tentativa de login recebida:", request.body);
      try {
        const { identifier, password } = loginSchema.parse(request.body);
        const { data: user, error } = await supabase.from("users").select("*").or(`email.eq."${identifier}",name.eq."${identifier}"`).maybeSingle();
        if (error) {
          console.error("\u274C Erro no Supabase:", error);
          return reply.status(500).send({ message: "Erro ao consultar banco de dados." });
        }
        if (!user) {
          console.log("\u26A0\uFE0F Usu\xE1rio n\xE3o encontrado:", identifier);
          return reply.status(401).send({ message: "Credenciais inv\xE1lidas (Usu\xE1rio n\xE3o existe)" });
        }
        if (!user.password) {
          return reply.status(401).send({ message: "Este usu\xE1rio n\xE3o possui senha configurada." });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          console.log("\u26A0\uFE0F Senha incorreta para:", identifier);
          return reply.status(401).send({ message: "Credenciais inv\xE1lidas (Senha incorreta)" });
        }
        const token = app.jwt.sign({
          sub: user.id.toString(),
          name: user.name,
          email: user.email,
          avatar_url: user.avatar_url,
          is_admin: user.is_admin || false
        }, { expiresIn: "7 days" });
        delete user.password;
        console.log("\u2705 Login Sucesso:", user.email);
        return { user, token };
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("\u{1F525} EXCE\xC7\xC3O CR\xCDTICA NO LOGIN:", error);
        return reply.status(500).send({ message: "Erro interno no servidor ao tentar logar." });
      }
    });
    app.put("/profile/update", async (request, reply) => {
      try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const body = updateProfileSchema.parse(request.body);
        if (Object.keys(body).length === 0) {
          return reply.status(400).send({ message: "Nenhum dado fornecido para atualiza\xE7\xE3o." });
        }
        const { data, error } = await supabase.from("users").update(body).eq("id", userId).select().single();
        if (error) throw error;
        if (data) delete data.password;
        return reply.status(200).send({ user: data });
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro ao atualizar perfil:", error);
        return reply.status(500).send({ message: "Erro interno ao atualizar perfil." });
      }
    });
    app.post("/forgot-password", async (request, reply) => {
      try {
        const { email } = forgotPasswordSchema.parse(request.body);
        const { data: user } = await supabase.from("users").select("id").eq("email", email).single();
        if (user) {
          const resetToken = crypto.randomBytes(32).toString("hex");
          const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
          const expires = new Date(Date.now() + 36e5);
          await supabase.from("users").update({ reset_token: hashedToken, reset_token_expires: expires.toISOString() }).eq("id", user.id);
          const resetUrl = `https://lock-front.onrender.com/reset-password/${resetToken}`;
          const resend = new Resend(process.env.RESEND_API_KEY);
          await resend.emails.send({
            from: "LOCK Platform <onboarding@resend.dev>",
            to: email,
            subject: "O seu Link de Redefini\xE7\xE3o de Palavra-passe",
            html: `<p>Clique aqui para redefinir: <a href="${resetUrl}">Redefinir Palavra-passe</a>.</p>`
          });
        }
        return { message: "Se um utilizador com este e-mail existir, um link de redefini\xE7\xE3o foi enviado." };
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro em forgot-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
      }
    });
    app.post("/reset-password", async (request, reply) => {
      try {
        const { token, password } = resetPasswordSchema.parse(request.body);
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        const { data: user, error } = await supabase.from("users").select("*").eq("reset_token", hashedToken).single();
        if (error || !user || new Date(user.reset_token_expires) < /* @__PURE__ */ new Date()) {
          return reply.status(400).send({ error: "Token inv\xE1lido ou expirado." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await supabase.from("users").update({ password: hashedPassword, reset_token: null, reset_token_expires: null }).eq("id", user.id);
        return { message: "Palavra-passe redefinida com sucesso!" };
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro em reset-password:", error);
        return reply.status(500).send({ error: "Erro interno no servidor." });
      }
    });
    app.get("/modules", async (request, reply) => {
      try {
        const { data: modules, error } = await supabase.from("exam_modules").select("*").order("created_at", { ascending: false });
        if (error) throw error;
        return reply.send(modules);
      } catch (error) {
        console.error("Erro ao buscar m\xF3dulos:", error);
        return reply.status(500).send({ message: "Erro ao carregar simulados." });
      }
    });
    var getQuizQuestionsSchema = z.object({
      topic: z.string(),
      difficulty: z.enum(["f\xE1cil", "m\xE9dio", "dif\xEDcil", "aleat\xF3rio", "temporizado", "treinamento"]),
      limit: z.coerce.number().int().positive().optional().default(10)
    });
    app.get("/quiz/questions", async (request, reply) => {
      try {
        await request.jwtVerify();
        const { topic, difficulty, limit } = getQuizQuestionsSchema.parse(request.query);
        let query = supabase.from("questions").select("*");
        if (topic !== "variado") {
          query = query.eq("topic", topic);
        }
        if (difficulty && !["aleat\xF3rio", "temporizado", "treinamento"].includes(difficulty)) {
          query = query.eq("difficulty", difficulty);
        }
        const { data: questions, error } = await query;
        if (error) throw error;
        if (!questions || questions.length === 0) {
          return reply.status(404).send({ message: "Nenhuma pergunta encontrada." });
        }
        const shuffled = questions.sort(() => 0.5 - Math.random());
        const selectedQuestions = shuffled.slice(0, limit);
        return reply.send(selectedQuestions);
      } catch (error) {
        console.error("Erro ao buscar perguntas do quiz:", error);
        return reply.status(500).send({ error: "Erro ao buscar perguntas" });
      }
    });
    app.get("/library/all", async (request, reply) => {
      try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { data, error } = await supabase.rpc("get_user_library_data", {
          p_user_id: userId
        });
        if (error) throw error;
        return data;
      } catch (error) {
        console.error("Erro ao buscar dados da biblioteca:", error);
        return reply.status(500).send({ error: "Erro ao buscar dados da biblioteca" });
      }
    });
    app.put("/library/status", async (request, reply) => {
      try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { materialId, status } = z.object({
          materialId: z.string().uuid(),
          status: z.string()
        }).parse(request.body);
        const { error } = await supabase.rpc("update_user_material_status", {
          p_user_id: userId,
          p_material_id: materialId,
          p_status: status
        });
        if (error) throw error;
        return reply.status(200).send({ message: "Status atualizado com sucesso" });
      } catch (error) {
        console.error("Erro ao atualizar status do material:", error);
        return reply.status(500).send({
          error: "Erro ao atualizar status",
          details: error.message || error
        });
      }
    });
    app.put("/library/last-accessed/:materialId", async (request, reply) => {
      try {
        await request.jwtVerify();
        const userId = request.user.sub;
        const { materialId } = z.object({ materialId: z.string().uuid() }).parse(request.params);
        const { error } = await supabase.from("users").update({ last_accessed_material_id: materialId }).eq("id", userId);
        if (error) throw error;
        return reply.status(200).send({ message: "\xDAltimo material acessado salvo com sucesso" });
      } catch (error) {
        console.error("Erro ao salvar \xFAltimo material acessado:", error);
        return reply.status(500).send({ error: "Erro ao salvar \xFAltimo material acessado" });
      }
    });
    app.post("/labs/sql-injection/1", async (request, reply) => {
      const { username, password } = request.body;
      if (username?.includes("'") || password?.includes("'")) {
        return reply.status(500).send({
          success: true,
          message: "Internal Server Error: Erro na sintaxe da sua consulta SQL. O banco de dados parece ser vulner\xE1vel."
        });
      }
      return reply.status(401).send({
        success: false,
        message: "Usu\xE1rio ou senha inv\xE1lidos."
      });
    });
    app.post("/labs/sql-injection/2", async (request, reply) => {
      const { username, password } = request.body;
      if (username === `administrator'--`) {
        return reply.send({ success: true, message: "Autentica\xE7\xE3o bypassada com sucesso! Redirecionando para o painel de controle..." });
      }
      return reply.status(401).send({ success: false, message: "Credenciais incorretas." });
    });
    app.post("/labs/sql-injection/3", async (request, reply) => {
      const { username, password } = request.body;
      const unionPayload = `' UNION SELECT 'Sup3r_S3cr3t_P4ss', NULL --`;
      if (username.toLowerCase().includes(unionPayload.toLowerCase())) {
        return reply.send({ success: true, message: "Login bem-sucedido! Bem-vindo de volta, Sup3r_S3cr3t_P4ss." });
      }
      return reply.status(401).send({ success: false, message: "Usu\xE1rio n\xE3o encontrado." });
    });
    app.post("/labs/brute-force/1", async (request, reply) => {
      const validUsers = ["admin", "guest"];
      const { username } = request.body;
      if (validUsers.includes(username)) {
        return reply.status(401).send({ success: false, message: "Senha incorreta." });
      }
      return reply.status(401).send({ success: false, message: "Usu\xE1rio n\xE3o encontrado." });
    });
    var generateRandomPassword = () => {
      return Math.random().toString(36).slice(-8);
    };
    app.post("/labs/brute-force/2/start", async (request, reply) => {
      const password = generateRandomPassword();
      const labToken = await reply.jwtSign({ password }, { expiresIn: "15m" });
      return { labToken };
    });
    app.post("/labs/brute-force/2", async (request, reply) => {
      try {
        const { passwordGuess, labToken } = request.body;
        if (!labToken) {
          return reply.status(400).send({ success: false, message: "Token do laborat\xF3rio n\xE3o fornecido." });
        }
        const decodedToken = app.jwt.verify(labToken);
        const correctPassword = decodedToken.password;
        if (passwordGuess === correctPassword) {
          return reply.send({ success: true, message: `Acesso concedido! Senha "${correctPassword}" encontrada.` });
        } else {
          return reply.status(401).send({ success: false, message: "Senha incorreta." });
        }
      } catch (error) {
        return reply.status(401).send({ success: false, message: "Token do laborat\xF3rio inv\xE1lido ou expirado. Recarregue a p\xE1gina." });
      }
    });
    var bruteForceTracker = {};
    app.post("/labs/brute-force/3", async (request, reply) => {
      const ip = request.ip;
      if (!bruteForceTracker[ip]) {
        bruteForceTracker[ip] = { attempts: 0, lockUntil: null };
      }
      const tracker = bruteForceTracker[ip];
      if (tracker.lockUntil && Date.now() < tracker.lockUntil) {
        const timeLeft = Math.ceil((tracker.lockUntil - Date.now()) / 1e3);
        return reply.status(429).send({ success: false, message: `Muitas tentativas falhas. Tente novamente em ${timeLeft} segundos.` });
      }
      tracker.lockUntil = null;
      const { password } = request.body;
      if (password === "4815") {
        tracker.attempts = 0;
        return reply.send({ success: true, message: "Acesso concedido! Prote\xE7\xE3o de rate limit contornada." });
      } else {
        tracker.attempts++;
        if (tracker.attempts >= 3) {
          tracker.lockUntil = Date.now() + 6e4;
          tracker.attempts = 0;
          return reply.status(429).send({ success: false, message: `Muitas tentativas falhas. Tente novamente em 60 segundos.` });
        }
        return reply.status(401).send({ success: false, message: "Credenciais incorretas." });
      }
    });
    app.post("/admin/questions", async (request, reply) => {
      try {
        await request.jwtVerify();
        const user = request.user;
        if (!user.is_admin) {
          return reply.status(403).send({ message: "Acesso negado. Apenas administradores." });
        }
        const body = createQuestionSchema.parse(request.body);
        if (!body.options.includes(body.correct_answer)) {
          return reply.status(400).send({ message: "A resposta correta deve ser uma das op\xE7\xF5es fornecidas." });
        }
        const { error } = await supabase.from("questions").insert({
          topic: body.topic,
          difficulty: body.difficulty,
          question: body.question,
          options: body.options,
          correct_answer: body.correct_answer,
          module_id: body.module_id || null
        });
        if (error) throw error;
        return reply.status(201).send({ message: "Quest\xE3o cadastrada com sucesso!" });
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro ao cadastrar quest\xE3o:", error);
        return reply.status(500).send({ message: "Erro interno ao salvar quest\xE3o." });
      }
    });
    {
    }
    app.post("/admin/materials", async (request, reply) => {
      try {
        await request.jwtVerify();
        const user = request.user;
        if (!user.is_admin) {
          return reply.status(403).send({ message: "\u26D4 Acesso negado. Apenas administradores." });
        }
        const body = createMaterialSchema.parse(request.body);
        const { error } = await supabase.from("books").insert({
          title: body.title,
          author: body.author,
          synopsis: body.synopsis,
          type: body.type,
          cover_url: body.cover_url,
          pdf_url: body.pdf_url,
          total_pages: body.total_pages || 0
        });
        if (error) throw error;
        return reply.status(201).send({ message: "\u{1F4DA} Material cadastrado com sucesso!" });
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro ao cadastrar material:", error);
        return reply.status(500).send({ message: "Erro interno ao salvar material." });
      }
    });
    app.post("/admin/modules", async (request, reply) => {
      try {
        await request.jwtVerify();
        const user = request.user;
        if (!user.is_admin) {
          return reply.status(403).send({ message: "\u26D4 Acesso negado. Apenas administradores." });
        }
        const body = createModuleSchema.parse(request.body);
        const { error } = await supabase.from("exam_modules").insert({
          title: body.title,
          description: body.description,
          cover_url: body.cover_url,
          difficulty_level: body.difficulty_level
        });
        if (error) throw error;
        return reply.status(201).send({ message: "\u{1F3C6} M\xF3dulo de Simulado criado com sucesso!" });
      } catch (error) {
        if (error instanceof z.ZodError) {
          return reply.status(400).send({ message: "Dados inv\xE1lidos.", issues: error.format() });
        }
        console.error("Erro ao criar m\xF3dulo:", error);
        return reply.status(500).send({ message: "Erro interno ao salvar m\xF3dulo." });
      }
    });
    var xssCommentsDb = [];
    var xssCommentsDbFiltered = [];
    app.post("/labs/xss/2", async (request, reply) => {
      const { author, site, comment } = request.body;
      xssCommentsDb.push({ author, site, comment });
      return reply.send({ success: true });
    });
    app.get("/labs/xss/2/comments", async (request, reply) => {
      return reply.send(xssCommentsDb);
    });
    app.post("/labs/xss/3", async (request, reply) => {
      let { author, site, comment } = request.body;
      site = site.replace(/alert/gi, "").replace(/<script>/gi, "");
      xssCommentsDbFiltered.push({ author, site, comment });
      return reply.send({ success: true });
    });
    app.get("/labs/xss/3/comments", async (request, reply) => {
      return reply.send(xssCommentsDbFiltered);
    });
    app.listen({
      host: "0.0.0.0",
      port: process.env.PORT ? Number(process.env.PORT) : 3333
    }).then(() => {
      console.log("\u{1F680} Servidor a rodar com CORS ativado em http://localhost:3333");
    });
  }
});
export default require_server();
