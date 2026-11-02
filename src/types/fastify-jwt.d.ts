import '@fastify/jwt';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: {
      sub: string;
      name: string;
      email: string; // <-- A LINHA QUE FALTAVA
      avatar_url?: string;
      is_admin?: boolean;
      // Presente só em tokens efêmeros de laboratório (ex. brute-force nível 2),
      // que carregam um labId opaco em vez de identificar um usuário de verdade
      // (a senha-alvo fica só na memória do servidor, nunca no token).
      // O claim `scope` distingue esse tipo de token de um token de sessão real.
      scope?: string;
      labId?: string;
    };
    user: {
      sub: string;
      name: string;
      email: string; // <-- E A LINHA QUE FALTAVA AQUI
      avatar_url?: string;
      is_admin?: boolean;
      scope?: string;
      password?: string;
    };
  }
}