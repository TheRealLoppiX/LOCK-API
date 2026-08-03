// Cliente HTTP fino para o LOCKIA-API — o LOCK-API não tem mais nenhuma
// lógica de IA local, só repassa pra lá. Sempre encaminha o mesmo header
// Authorization que a própria rota já recebeu (já verificado uma vez aqui;
// o LOCKIA-API verifica de novo, de forma independente, com o mesmo
// APP_JWT_SECRET — sem atalho de confiança entre os dois serviços).
const LOCKIA_API_URL = process.env.LOCKIA_API_URL;

async function callLockia<T>(path: string, authorization: string, body: unknown): Promise<T> {
  if (!LOCKIA_API_URL) throw new Error('LOCKIA_API_URL não configurada.');

  const response = await fetch(`${LOCKIA_API_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: authorization,
    },
    body: JSON.stringify(body),
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.message || `LOCKIA-API respondeu ${response.status} em ${path}`);
  }
  return data as T;
}

export const lockiaClient = {
  chat: (authorization: string, body: { message: string; attachments?: unknown[]; history?: unknown[] }) =>
    callLockia<{ response: string }>('/chat', authorization, body),

  analyzeQuiz: (authorization: string, wrongQuestions: string[]) =>
    callLockia<{ analysis: string }>('/analyze-quiz', authorization, { wrongQuestions }),

  moderateImage: (authorization: string, data: string, mimeType: string) =>
    callLockia<{ explicit: boolean }>('/moderate-image', authorization, { data, mimeType }),

  generateQuestions: (authorization: string, tema: string, quantidade: number) =>
    callLockia<{ questoes: unknown[] }>('/generate-questions', authorization, { tema, quantidade }),
};
