"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/server.ts
var import_config = require("dotenv/config");
var import_fastify = __toESM(require("fastify"));
var import_cors = __toESM(require("@fastify/cors"));

// src/supabaseConnection.ts
var import_supabase_js = require("@supabase/supabase-js");
var import_dotenv = __toESM(require("dotenv"));
import_dotenv.default.config();
var supaBaseURL = process.env.SUPABASEURL || "https://grcxqjrodvulxnhtrqhq.supabase.co";
var supaBaseKEY = process.env.SUPABASEKEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdyY3hxanJvZHZ1bHhuaHRycWhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY3MzgyMjMsImV4cCI6MjA3MjMxNDIyM30.8VGjs7HtQ32ZLvGPV8MZTIiftucZmlW0rw9jlYQzraw";
var supabase = (0, import_supabase_js.createClient)(supaBaseURL, supaBaseKEY, {
  auth: {
    persistSession: false
  }
});

// src/server.ts
var import_bcrypt = __toESM(require("bcrypt"));
var import_crypto = __toESM(require("crypto"));
var import_resend = require("resend");
var app = (0, import_fastify.default)();
app.register(import_cors.default, {
  origin: "http://localhost:3000",
  methods: ["GET", "POST", "PUT", "DELETE"]
});
app.post("/register", async (request, reply) => {
  try {
    const { name, email, password } = request.body;
    const { data: exists } = await supabase.from("users").select("email").eq("email", email).single();
    if (exists) {
      return reply.status(400).send({ error: "Email j\xE1 cadastrado" });
    }
    const saltRounds = 10;
    const hashedPassword = await import_bcrypt.default.hash(password, saltRounds);
    const { data, error } = await supabase.from("users").insert([{ name, email, password: hashedPassword }]).select().single();
    if (error) throw error;
    if (data) {
      delete data.password;
    }
    return { user: data };
  } catch (error) {
    console.error("Erro no registro:", error);
    return reply.status(500).send({ error: "Erro ao registrar usu\xE1rio" });
  }
});
app.post("/login", async (request, reply) => {
  try {
    const { identifier, password } = request.body;
    const { data: user, error } = await supabase.from("users").select("*").or(`email.eq.${identifier},name.eq.${identifier}`).single();
    if (error || !user) {
      return reply.status(401).send({ error: "Credenciais inv\xE1lidas" });
    }
    const passwordMatch = await import_bcrypt.default.compare(password, user.password);
    if (!passwordMatch) {
      return reply.status(401).send({ error: "Credenciais inv\xE1lidas" });
    }
    delete user.password;
    return { user };
  } catch (error) {
    console.error("Erro no login:", error);
    return reply.status(500).send({ error: "Erro no login" });
  }
});
app.post("/forgot-password", async (request, reply) => {
  try {
    const { email } = request.body;
    const resend = new import_resend.Resend(process.env.RESEND_API_KEY);
    const { data: user } = await supabase.from("users").select("id").eq("email", email).single();
    if (!user) {
      return { message: "Se um usu\xE1rio com este e-mail existir, um link de redefini\xE7\xE3o ser\xE1 enviado." };
    }
    const resetToken = import_crypto.default.randomBytes(32).toString("hex");
    const hashedToken = import_crypto.default.createHash("sha256").update(resetToken).digest("hex");
    const expires = /* @__PURE__ */ new Date();
    expires.setHours(expires.getHours() + 1);
    await supabase.from("users").update({ reset_token: hashedToken, reset_token_expires: expires.toISOString() }).eq("id", user.id);
    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;
    await resend.emails.send({
      from: "LOCK Platform <onboarding@resend.dev>",
      to: email,
      subject: "Seu Link de Redefini\xE7\xE3o de Senha",
      html: `
              <h1>Redefini\xE7\xE3o de Senha</h1>
              <p>Voc\xEA solicitou uma redefini\xE7\xE3o de senha. Clique no link abaixo para criar uma nova senha:</p>
              <a href="${resetUrl}" style="background-color: #00bfff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                Redefinir Senha
              </a>
              <p>Este link expira em 1 hora.</p>
            `
    });
    return { message: "Se um usu\xE1rio com este e-mail existir, um link de redefini\xE7\xE3o foi enviado." };
  } catch (error) {
    console.error("Erro em forgot-password:", error);
    return reply.status(500).send({ error: "Erro interno no servidor." });
  }
});
app.post("/reset-password", async (request, reply) => {
  try {
    const { token, password } = request.body;
    const hashedToken = import_crypto.default.createHash("sha256").update(token).digest("hex");
    const { data: user, error } = await supabase.from("users").select("*").eq("reset_token", hashedToken).single();
    if (error || !user || new Date(user.reset_token_expires) < /* @__PURE__ */ new Date()) {
      return reply.status(400).send({ error: "Token inv\xE1lido ou expirado." });
    }
    const saltRounds = 10;
    const hashedPassword = await import_bcrypt.default.hash(password, saltRounds);
    const { error: updateError } = await supabase.from("users").update({
      password: hashedPassword,
      reset_token: null,
      reset_token_expires: null
    }).eq("id", user.id);
    if (updateError) throw updateError;
    return { message: "Senha redefinida com sucesso! Voc\xEA ser\xE1 redirecionado para o login." };
  } catch (error) {
    console.error("Erro em reset-password:", error);
    return reply.status(500).send({ error: "Erro interno no servidor." });
  }
});
app.listen({
  host: "0.0.0.0",
  port: process.env.PORT ? Number(process.env.PORT) : 3333
}).then(() => {
  console.log("\u{1F680} Servidor rodando com CORS ativado em http://localhost:3333");
});
