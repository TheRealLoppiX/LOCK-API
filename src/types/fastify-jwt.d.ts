// Conteúdo do arquivo: src/types/fastify-jwt.d.ts

import '@fastify/jwt';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    // A payload é o conteúdo "dentro" do seu token
    payload: {
      sub: string; // 'sub' é o ID do usuário, padrão do JWT
      // adicione aqui outras propriedades que seu token possa ter
    };
    // O user é um atalho para a payload decodificada
    user: {
      sub: string;
      // espelhe as mesmas propriedades da payload
    };
  }
}