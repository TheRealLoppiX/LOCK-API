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
      // que carregam a senha-alvo em vez de identificar um usuário de verdade.
      // O claim `scope` distingue esse tipo de token de um token de sessão real.
      scope?: string;
      password?: string;
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