// Cliente HTTP fino para o LOCKIA-API — o LOCK-API não tem mais nenhuma
// lógica de IA local, só repassa pra lá. Sempre encaminha o mesmo header
// Authorization que a própria rota já recebeu (já verificado uma vez aqui;
// o LOCKIA-API verifica de novo, de forma independente, com o mesmo
// APP_JWT_SECRET — sem atalho de confiança entre os dois serviços).
const LOCKIA_API_URL = process.env.LOCKIA_API_URL;

// Plano free do Render: cold start pode passar de 50s, então o teto é largo.
const REQUEST_TIMEOUT_MS = 90_000;
// Status transitórios (rate limit/throttle da plataforma, serviço acordando
// ou fora do ar) — vale uma única nova tentativa antes de desistir.
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);
const MAX_RETRY_DELAY_MS = 5_000;
const DEFAULT_RETRY_DELAY_MS = 1_500;

// Erro com o status real devolvido pelo LOCKIA-API (ou 0 quando nem houve
// resposta: rede/timeout), pra rota decidir o que mostrar ao usuário em vez
// de transformar tudo num 500 genérico.
export class LockiaError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'LockiaError';
  }
}

// Nem toda resposta de erro vem em JSON — um 429 da borda do Render/Cloudflare
// chega como "Too Many Requests" em texto puro. Lê como texto e só depois
// tenta interpretar, nunca deixando o parse derrubar a requisição.
function parseBody(text: string): any {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function retryDelayMs(response: Response): number {
  const retryAfter = Number(response.headers.get('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0) {
    return Math.min(retryAfter * 1000, MAX_RETRY_DELAY_MS);
  }
  return DEFAULT_RETRY_DELAY_MS;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function callLockia<T>(path: string, authorization: string, body: unknown): Promise<T> {
  if (!LOCKIA_API_URL) throw new Error('LOCKIA_API_URL não configurada.');

  for (let attempt = 1; ; attempt++) {
    let response: Response;
    try {
      response = await fetch(`${LOCKIA_API_URL}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: authorization,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (networkError) {
      // Sem nova tentativa em falha de rede/timeout: um timeout já esperou
      // 90s, e repetir dobraria a espera do usuário.
      throw new LockiaError(`Falha de rede/timeout ao chamar ${path}: ${(networkError as Error).message}`, 0);
    }

    const text = await response.text();
    const data = parseBody(text);

    if (response.ok) {
      if (data === null) {
        throw new LockiaError(`LOCKIA-API respondeu ${response.status} sem JSON válido em ${path}`, 502);
      }
      return data as T;
    }

    if (attempt === 1 && RETRYABLE_STATUS.has(response.status)) {
      await sleep(retryDelayMs(response));
      continue;
    }

    const detail = data?.message || text.slice(0, 200) || 'sem corpo';
    throw new LockiaError(`LOCKIA-API respondeu ${response.status} em ${path}: ${detail}`, response.status);
  }
}

// Traduz uma falha do LOCKIA-API na resposta HTTP que a rota deve devolver
// ao cliente. Devolve null para erros que não são do LOCKIA-API — a rota
// segue com seu próprio tratamento (500 genérico).
export function lockiaErrorReply(error: unknown): { status: number; message: string } | null {
  if (!(error instanceof LockiaError)) return null;

  if (error.status === 429) {
    return { status: 429, message: 'A IA está recebendo muitas requisições agora. Aguarde alguns segundos e tente novamente.' };
  }
  if (error.status === 0 || error.status >= 500) {
    return { status: 503, message: 'A IA está temporariamente indisponível. Tente novamente em instantes.' };
  }
  // 401/403 aqui significa que o LOCKIA-API recusou um token que o LOCK-API
  // aceitou (segredo dessincronizado) — problema de configuração, não da
  // sessão do usuário; não repassa o 401 pra não deslogar ninguém à toa.
  if (error.status === 401 || error.status === 403) {
    return { status: 502, message: 'Não foi possível falar com o serviço de IA agora.' };
  }
  return null;
}

export const lockiaClient = {
  // persona: 'aegis' avisa o LOCKIA-API que quem está chamando é o chat
  // embutido do LOCK — sem isso, a IA responde como "IA do LOCKIA" mesmo
  // aqui, já que os dois produtos passam pelo mesmo endpoint /chat.
  chat: (authorization: string, body: { message: string; attachments?: unknown[]; history?: unknown[] }) =>
    callLockia<{ response: string }>('/chat', authorization, { ...body, persona: 'aegis' }),

  analyzeQuiz: (authorization: string, wrongQuestions: string[]) =>
    callLockia<{ analysis: string }>('/analyze-quiz', authorization, { wrongQuestions }),

  moderateImage: (authorization: string, data: string, mimeType: string) =>
    callLockia<{ explicit: boolean }>('/moderate-image', authorization, { data, mimeType }),

  generateQuestions: (authorization: string, tema: string, quantidade: number) =>
    callLockia<{ questoes: unknown[] }>('/generate-questions', authorization, { tema, quantidade }),
};
