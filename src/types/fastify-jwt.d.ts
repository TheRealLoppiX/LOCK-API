import '@fastify/jwt';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: {
      sub: string;
      name: string;
      email: string; // <-- A LINHA QUE FALTAVA
      avatar_url?: string;
    };
    user: {
      sub: string;
      name: string;
      email: string; // <-- E A LINHA QUE FALTAVA AQUI
      avatar_url?: string;
    };
  }
}