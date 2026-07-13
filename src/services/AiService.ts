const GROQ_API_KEY = process.env.GROQ_API_KEY;
const API_URL = "https://api.groq.com/openai/v1/chat/completions";

export const aiService = {
  askAegis: async (prompt: string, maxTokens: number = 800) => {
    try {
      if (!GROQ_API_KEY) throw new Error("Chave Groq não configurada.");

      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile", 
          messages: [
            { 
              role: "system", 
              content: `Você é Aegis, IA oficial do Laboratório Online de Cibersegurança com Kali Linux (LOCK). Ensine cibersegurança, Kali Linux, Linux, redes, programação, forense, defesa, CTFs e pentest apenas em ambientes autorizados. 
              Responda de forma clara, precisa e adequada ao nível do usuário. Não forneça instruções para invasões, malware, roubo de dados, fraude ou ataques contra terceiros. 
              Em temas sensíveis, limite-se a teoria, laboratórios controlados e defesa. Se não souber algo, admita.` 
            },
            { role: "user", content: prompt }
          ],
          max_tokens: maxTokens,
          temperature: 0.7,
        }),
      });

      const data = await response.json();
      if (data.error) throw new Error(data.error.message);

      return data.choices[0].message.content.trim();
    } catch (error) {
      console.error("Erro na Groq:", error);
      return "Estou processando muitas informações agora. Tente novamente em breve!";
    }
  },

  analisarErros: async (erros: string[]) => {
    const prompt = `Um aluno errou estas questões: ${erros.join(", ")}. Explique brevemente os conceitos e dê uma dica de estudo encorajadora.`;
    return await aiService.askAegis(prompt, 1000);
  },

  gerarQuestoesIA: async (tema: string, quantidade: number) => {
    const prompt = `Gere um JSON com exatamente ${quantidade} questões sobre ${tema}. 
    Siga este formato: [{"enunciado": "...", 
                         "opcao_a": "...", 
                         "opcao_b": "...", 
                         "opcao_c": "...", 
                         "opcao_d": "...", 
                         "opcao_e": "...",
                         "resposta_correta": "A, B, C, D ou E", 
                         "justificativa": "...",
                         "referencia": "..."}]
    Retorne APENAS o JSON, sem explicações.`;
    
    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          messages: [{ role: "user", content: prompt }],
          response_format: { type: "json_object" }, 
          temperature: 0.2,
        }),
      });

      const data = await response.json();
      const content = data.choices[0].message.content;
      
      const parsed = JSON.parse(content);
      return Array.isArray(parsed) ? parsed : (parsed.questions || parsed.questoes);
    } catch (error) {
      console.error("Erro ao gerar questões:", error);
      throw error;
    }
  }
};