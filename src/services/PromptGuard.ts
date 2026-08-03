// Varredura local, sem custo de IA, por padrões conhecidos de tentativa de
// prompt injection — roda no LOCK-API ANTES de qualquer prompt de usuário
// ser repassado ao LOCKIA-API. É uma camada extra e barata (defesa em
// profundidade), não uma substituição do classificador de IA (camada 1)
// que o LOCKIA-API continua rodando de qualquer forma sobre todo o tráfego
// que recebe, inclusive o que vem daqui.
const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(as\s+)?instru[cç][oõ]es\s+anteriores/i,
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(all\s+)?(previous|above)\s+instructions/i,
  /you\s+are\s+now\s+/i,
  /voc[eê]\s+(agora\s+)?[eé]\s+(um|uma)\s+novo[a]?\s+(assistente|ia|ai|persona)/i,
  /system\s*:\s*/i,
  /\bact\s+as\s+(if\s+you\s+are\s+)?/i,
  /finja\s+(que\s+)?(ser|voc[eê]\s+[eé])/i,
  /reveal\s+(your\s+)?system\s+prompt/i,
  /revele\s+(o\s+)?(seu\s+)?prompt\s+(de\s+sistema|do\s+sistema)/i,
  /jailbreak/i,
  /modo\s+desenvolvedor/i,
  /developer\s+mode/i,
  /\bDAN\b/,
];

export function looksLikePromptInjection(text: string): boolean {
  return INJECTION_PATTERNS.some((pattern) => pattern.test(text));
}
