// O domínio schednext.com.br já está autenticado via DNS (SPF/DKIM) na conta
// Brevo, então qualquer remetente nele funciona sem verificação individual
// (diferente de tutuzao2016@gmail.com, que nunca foi verificado como sender
// e fazia a Brevo rejeitar o envio de forma assíncrona — ver HANDOFF).
const BREVO_SENDER = { name: 'LOCK Platform', email: 'lock@schednext.com.br' };

/**
 * Envia um e-mail transacional via Brevo. Nunca lança — falhas de envio
 * (rede ou resposta não-ok da Brevo) só são logadas, para não derrubar o
 * fluxo que disparou o e-mail (registro, redefinição de senha etc.).
 */
export async function sendEmail(to: string, subject: string, htmlContent: string): Promise<void> {
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
    }
  } catch (error) {
    console.error('Erro ao enviar e-mail via Brevo:', error);
  }
}
