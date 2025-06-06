// Ensure this binding name matches your D1 binding in Cloudflare dashboard
// const DB_BINDING = "DB";
// Ensure this env var name matches your env var in Cloudflare dashboard
// const MAIL_DOMAIN_ENV = "MAIL_DOMAIN";

const DB_SCHEMA = [
// No more DROP TABLE IF EXISTS for idempotent initialization
  `CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_address TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);`,
  `CREATE INDEX IF NOT EXISTS idx_mailboxes_email_address ON mailboxes (email_address);`,
  `CREATE INDEX IF NOT EXISTS idx_mailboxes_token ON mailboxes (token);`,
  `CREATE INDEX IF NOT EXISTS idx_mailboxes_created_at ON mailboxes (created_at);`,

  `CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY, -- Changed to TEXT for UUID
    mailbox_id INTEGER NOT NULL,
    message_id_header TEXT, -- Actual Message-ID from email header, can be NULL
    received_at INTEGER NOT NULL,
    from_address TEXT NOT NULL,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    raw_email_size INTEGER,
    attachments_count INTEGER DEFAULT 0,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);`,
  `CREATE INDEX IF NOT EXISTS idx_emails_mailbox_id ON emails (mailbox_id);`,
  `CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails (received_at);`,
// Optional: Index on message_id_header if you query it often for deduplication
  `CREATE INDEX IF NOT EXISTS idx_emails_message_id_header ON emails (message_id_header);`
];

async function initializeDB(env) {
  if (!env.DB) {
    return new Response("D1 Database (DB) binding not found.", { status: 500 });
  }
  try {
    // Check if tables exist by trying to query them.
    // A more robust check might query sqlite_master, but this is simpler for now.
    let mailboxesExist = false;
    let emailsExist = false;
    try {
      await env.DB.prepare("SELECT 1 FROM mailboxes LIMIT 1").first();
      mailboxesExist = true;
    } catch (e) { /* table does not exist */ }
    try {
      await env.DB.prepare("SELECT 1 FROM emails LIMIT 1").first();
      emailsExist = true;
    } catch (e) { /* table does not exist */ }

    if (mailboxesExist && emailsExist) {
      return new Response("Database schema already exists.\n\n" + DB_SCHEMA.join("\n\n"), {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // If one or both don't exist, run the full schema.
    // This is still safe because of "IF NOT EXISTS"
    const results = await env.DB.batch(DB_SCHEMA.map(sql => env.DB.prepare(sql)));
    console.log("Database initialization results (some might be no-ops if tables partially existed):", results);
    return new Response("Database schema initialized (or updated if partially existed).\n\n" + DB_SCHEMA.join("\n\n"), {
      headers: { "Content-Type": "text/plain" },
    });
  } catch (e) {
    console.error("DB Initialization Error:", e);
    return new Response(`Database initialization failed: ${e.message}`, { status: 500 });
  }
}

function generateRandomString(length = 8) {
  const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function errorResponse(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function authenticate(request, env) {
  const token = request.headers.get('Authorization');
  if (!token) {
    return null;
  }
  try {
    const { results } = await env.DB.prepare(
      "SELECT id, email_address FROM mailboxes WHERE token = ?"
    ).bind(token).all();
    return results.length ? results[0] : null;
  } catch (e) {
    console.error("Auth DB error:", e);
    return null;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!env.MAIL_DOMAIN) {
      return errorResponse("MAIL_DOMAIN environment variable not set.", 500);
    }
    if (!env.DB) {
      return errorResponse("D1 Database (DB) binding not configured.", 500);
    }
    const mailDomain = env.MAIL_DOMAIN.toLowerCase();


    if (url.pathname === '/' && request.method === 'GET') {
      return initializeDB(env);
    }


    if (url.pathname === '/mailbox' && request.method === 'POST') {
      try {
        let mailboxAddress;
        let token;
        let attempts = 0;
        const maxAttempts = 10; // Increased attempts slightly

        while (attempts < maxAttempts) {
          const prefix = generateRandomString(10); // Prefix remains random case
          mailboxAddress = `${prefix}@${mailDomain}`.toLowerCase(); // Stored as lowercase
          token = crypto.randomUUID();

          try {
            const stmt = env.DB.prepare(
              "INSERT INTO mailboxes (email_address, token, created_at) VALUES (?, ?, ?)"
            );
            await stmt.bind(mailboxAddress, token, Math.floor(Date.now() / 1000)).run();
            break;
          } catch (e) {
            if (e.message && e.message.toLowerCase().includes("unique constraint failed")) {
              attempts++;
              if (attempts >= maxAttempts) {
                console.error("Failed to create unique mailbox/token after multiple attempts:", e.message);
                return errorResponse("Could not create mailbox, please try again.", 500);
              }
            } else {
              throw e;
            }
          }
        }
        if (attempts >= maxAttempts) {
          return errorResponse("Could not create mailbox due to high collision rate, please try again later.", 500);
        }

        return jsonResponse({ token, mailbox: mailboxAddress }, 201);
      } catch (e) {
        console.error("Create mailbox error:", e);
        return errorResponse(`Failed to create mailbox: ${e.message}`, 500);
      }
    }


    if (url.pathname === '/messages' && request.method === 'GET') {
      const mailboxInfo = await authenticate(request, env);
      if (!mailboxInfo) {
        return errorResponse("Unauthorized: Invalid or missing token.", 401);
      }

      try {
        const { results } = await env.DB.prepare(
          // id is now a UUID string, so toString() is not strictly needed but harmless
          "SELECT id, received_at, from_address, subject, body_text, attachments_count FROM emails WHERE mailbox_id = ? ORDER BY received_at DESC"
        ).bind(mailboxInfo.id).all();

        const messages = results.map(row => ({
          _id: row.id, // id is already a UUID string
          receivedAt: row.received_at,
          from: row.from_address,
          subject: row.subject || "",
          bodyPreview: row.body_text ? (row.body_text.length > 100 ? row.body_text.substring(0, 100) + "..." : row.body_text) : "",
          attachmentsCount: row.attachments_count || 0,
        }));

        return jsonResponse({
          mailbox: mailboxInfo.email_address,
          messages,
        });
      } catch (e) {
        console.error("Get messages error:", e);
        return errorResponse(`Failed to retrieve messages: ${e.message}`, 500);
      }
    }

    // Updated regex to match UUID for messageId
    const messageDetailMatch = url.pathname.match(/^\/messages\/([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})$/i);
    if (messageDetailMatch && request.method === 'GET') {
      const messageId = messageDetailMatch[1]; // This is the UUID string
      const mailboxInfo = await authenticate(request, env);
      if (!mailboxInfo) {
        return errorResponse("Unauthorized: Invalid or missing token.", 401);
      }

      try {
        const stmt = env.DB.prepare(
          "SELECT id, received_at, from_address, subject, body_text, body_html, attachments_count FROM emails WHERE id = ? AND mailbox_id = ?"
        );
        const row = await stmt.bind(messageId, mailboxInfo.id).first();

        if (!row) {
          return errorResponse("Message not found or access denied.", 404);
        }

        return jsonResponse({
          _id: row.id, // id is already a UUID string
          receivedAt: row.received_at,
          mailbox: mailboxInfo.email_address,
          from: row.from_address,
          subject: row.subject || "",
          bodyPreview: row.body_text ? (row.body_text.length > 100 ? row.body_text.substring(0, 100) + "..." : row.body_text) : "",
          bodyHtml: row.body_html || "",
          attachmentsCount: row.attachments_count || 0,
          attachments: []
        });
      } catch (e) {
        console.error("Get message detail error:", e);
        return errorResponse(`Failed to retrieve message detail: ${e.message}`, 500);
      }
    }

    return errorResponse("Not Found", 404);
  },

  async email(message, env, ctx) {
    if (!env.MAIL_DOMAIN) {
      console.error("MAIL_DOMAIN environment variable not set. Cannot process email.");
      return;
    }
    if (!env.DB) {
      console.error("D1 Database (DB) binding not configured. Cannot process email.");
      return;
    }
    const mailDomain = env.MAIL_DOMAIN.toLowerCase();

    const recipientHeader = message.to;
    if (!recipientHeader) {
      console.log("Email has no 'To' header. Ignoring.");
      // message.setReject("Missing recipient");
      return;
    }
    const recipient = recipientHeader.toLowerCase(); // Normalize recipient to lowercase

    if (!recipient.endsWith(`@${mailDomain}`)) {
      console.log(`Email to ${recipient} does not match MAIL_DOMAIN @${mailDomain}. Ignoring.`);
      return;
    }

    try {
      const mailboxStmt = env.DB.prepare("SELECT id FROM mailboxes WHERE email_address = ?");
      // Query with lowercase recipient, matching how it's stored
      const mailbox = await mailboxStmt.bind(recipient).first();

      if (!mailbox) {
        console.log(`Mailbox ${recipient} does not exist. Email not saved.`);
        // message.setReject(`Mailbox ${recipient} does not exist.`); // Optional
        return;
      }
      const mailboxId = mailbox.id;

      const from = (message.headers.get("from") || "unknown@example.com").toLowerCase();
      const subject = message.headers.get("subject") || "No Subject";
      // Get the original Message-ID header for storage, can be null
      const messageIdHeader = message.headers.get("message-id");

      let bodyText = "";
      let bodyHtml = "";
      try { bodyText = await message.text() || ""; } catch(e) { console.warn("Could not get text body", e.message); }
      try { bodyHtml = await message.html() || ""; } catch(e) { console.warn("Could not get html body", e.message); }

      let attachmentsCount = 0;
      if (message.attachments && Array.isArray(message.attachments)) {
        attachmentsCount = message.attachments.length;
      }

      const rawEmailSize = message.rawSize;
      const emailUuid = crypto.randomUUID(); // Generate UUID for our internal email ID

      const insertStmt = env.DB.prepare(
        "INSERT INTO emails (id, mailbox_id, message_id_header, received_at, from_address, subject, body_text, body_html, raw_email_size, attachments_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      );
      await insertStmt.bind(
        emailUuid,
        mailboxId,
        messageIdHeader, // Store the actual header
        Math.floor(Date.now() / 1000),
        from,
        subject,
        bodyText,
        bodyHtml,
        rawEmailSize,
        attachmentsCount
      ).run();

      console.log(`Email (ID: ${emailUuid}) for ${recipient} from ${from} saved successfully.`);

    } catch (e) {
      // Check for unique constraint violation on message_id_header if you add it as UNIQUE
      if (e.message && e.message.toLowerCase().includes("unique constraint failed") && messageIdHeader) {
        console.log(`Duplicate email based on Message-ID header: ${messageIdHeader}. Ignoring.`);
      } else {
        console.error(`Error processing email for ${recipient}:`, e);
        // message.setReject(`Processing error: ${e.message}`); // Optional
      }
    }
  },

  async scheduled(event, env, ctx) {
    console.log(`Cron event type: ${event.cron}`);
    if (!env.DB) {
      console.error("Scheduled task: D1 Database (DB) binding not configured.");
      return;
    }

    const oneDayAgo = Math.floor(Date.now() / 1000) - (24 * 60 * 60);
    let deletedEmailsCount = 0;
    let deletedMailboxesCount = 0;

    try {
      console.log(`Attempting to delete items older than timestamp: ${oneDayAgo}`);

      const deleteEmailsStmt = env.DB.prepare("DELETE FROM emails WHERE received_at < ?");
      const emailRes = await deleteEmailsStmt.bind(oneDayAgo).run();
      deletedEmailsCount = emailRes.meta.changes || 0; // D1 returns changes here
      console.log(`Deleted ${deletedEmailsCount} emails older than 1 day.`);

      const deleteMailboxesStmt = env.DB.prepare("DELETE FROM mailboxes WHERE created_at < ?");
      const mailboxRes = await deleteMailboxesStmt.bind(oneDayAgo).run();
      deletedMailboxesCount = mailboxRes.meta.changes || 0;
      console.log(`Deleted ${deletedMailboxesCount} mailboxes (and their tokens) older than 1 day.`);

    } catch (e) {
      console.error("Scheduled cleanup error:", e);
    }
    console.log(`Scheduled cleanup finished. Deleted ${deletedEmailsCount} emails and ${deletedMailboxesCount} mailboxes.`);
  }
};
