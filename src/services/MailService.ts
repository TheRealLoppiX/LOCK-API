// O domínio schednext.com.br já está autenticado via DNS (SPF/DKIM) na conta
// Brevo, então qualquer remetente nele funciona sem verificação individual
// (diferente de tutuzao2016@gmail.com, que nunca foi verificado como sender
// e fazia a Brevo rejeitar o envio de forma assíncrona — ver HANDOFF).
const BREVO_SENDER = { name: 'LOCK Platform', email: 'lock@schednext.com.br' };

/**
 * Envia um e-mail transacional via Brevo. Nunca lança — falhas de envio
 * (rede ou resposta não-ok da Brevo) só são logadas, para não derrubar o
 * fluxo que disparou o e-mail. Devolve se o envio foi aceito pela Brevo —
 * a maioria dos chamadores (redefinição de senha etc.) ignora esse retorno
 * de propósito, mas o cadastro agora depende disso: como a senha e o código
 * de verificação só existem nesse e-mail, sem um jeito de saber se ele saiu
 * de verdade o cadastro criaria contas inacessíveis para sempre.
 */
export async function sendEmail(to: string, subject: string, htmlContent: string): Promise<boolean> {
  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'api-key': process.env.BREVO_API_KEY!,
      },
      body: JSON.stringify({
        sender: BREVO_SENDER,
        to: [{ email: to }],
        subject,
        htmlContent,
      }),
    });
    if (!res.ok) {
      console.error('Erro ao enviar e-mail via Brevo:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (error) {
    console.error('Erro ao enviar e-mail via Brevo:', error);
    return false;
  }
}
