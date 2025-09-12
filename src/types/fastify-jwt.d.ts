import '@fastify/jwt';

declare module '@fastify/jwt' {
  // Este interface define o que está DENTRO do nosso token
  interface FastifyJWT {
    payload: {
      sub: string; // O ID do utilizador
      name: string;
      avatar_url?: string;
    };
    // O `request.user` será um atalho para a payload
    user: {
      sub: string;
      name: string;
      avatar_url?: string;
    };
  }
}