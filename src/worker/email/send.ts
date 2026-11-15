/**
 * Outbound mail via Resend API (when RESEND_API_KEY is configured) or
 * Cloudflare Email Sending (send_email binding).
 */
export interface OutgoingAttachment {
  /** Raw text or binary content. */
  content: string | ArrayBuffer | ArrayBufferView;
  filename: string;
  type: string;
  disposition: "attachment" | "inline";
  contentId?: string;
}

export interface OutgoingEmail {
  from: { address: string; name?: string };
  to: string[];
  subject: string;
  text: string;
  attachments?: OutgoingAttachment[];
  /** RFC Message-ID of the message being replied to */
  inReplyTo?: string;
  /** Full References chain, oldest first */
  references?: string[];
  /** Set for agent-sent mail so recipients' auto-responders stay quiet (RFC 3834) */
  autoSubmitted?: "auto-replied" | "auto-generated";
  /** Durable send-attempt id for tracing an ambiguous send in provider logs. */
  attemptId?: string;
}

export interface SendEmailEnv {
  RESEND_API_KEY?: string;
  EMAIL: {
    send(message: {
      from: string | { email: string; name?: string };
      to: string | Array<string | { email: string; name?: string }>;
      subject: string;
      text?: string;
      html?: string;
      attachments?: OutgoingAttachment[];
      headers?: Record<string, string>;
    }): Promise<{ messageId: string }>;
  };
}

export interface SendResult {
  messageId: string;
}

function toBase64(content: string | ArrayBuffer | ArrayBufferView): string {
  let bytes: Uint8Array;
  if (typeof content === "string") {
    bytes = new TextEncoder().encode(content);
  } else if (content instanceof ArrayBuffer) {
    bytes = new Uint8Array(content);
  } else {
    bytes = new Uint8Array(content.buffer, content.byteOffset, content.byteLength);
  }
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export async function sendEmail(env: SendEmailEnv, mail: OutgoingEmail): Promise<SendResult> {
  const headers: Record<string, string> = {};
  if (mail.inReplyTo) headers["In-Reply-To"] = mail.inReplyTo;
  if (mail.references?.length) headers["References"] = mail.references.join(" ");
  if (mail.autoSubmitted) headers["Auto-Submitted"] = mail.autoSubmitted;
  if (mail.attemptId) headers["X-Mailroom-Attempt"] = mail.attemptId;

  const resendKey = env.RESEND_API_KEY?.trim();
  if (resendKey) {
    const fromHeader = mail.from.name
      ? `${mail.from.name} <${mail.from.address}>`
      : mail.from.address;
    const attachments = mail.attachments?.map((att) => ({
      filename: att.filename,
      content: toBase64(att.content),
      content_type: att.type,
      ...(att.contentId ? { content_id: att.contentId } : {}),
    }));
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${resendKey}`,
        "Content-Type": "application/json",
        ...(mail.attemptId ? { "Idempotency-Key": mail.attemptId } : {}),
      },
      body: JSON.stringify({
        from: fromHeader,
        to: mail.to,
        subject: mail.subject,
        text: mail.text || " ",
        ...(attachments?.length ? { attachments } : {}),
        ...(Object.keys(headers).length ? { headers } : {}),
      }),
    });
    const data = (await response.json().catch(() => ({}))) as {
      id?: string;
      message?: string;
      name?: string;
    };
    if (!response.ok || !data.id) {
      throw new Error(data.message || `Resend error (${response.status})`);
    }
    return { messageId: `<${data.id}@resend.dev>` };
  }

  const result = await env.EMAIL.send({
    from: mail.from.name
      ? { email: mail.from.address, name: mail.from.name }
      : mail.from.address,
    to: mail.to,
    subject: mail.subject,
    text: mail.text,
    ...(mail.attachments?.length ? { attachments: mail.attachments } : {}),
    headers,
  });

  const messageId = result.messageId.startsWith("<")
    ? result.messageId
    : `<${result.messageId}>`;
  return { messageId };
}
