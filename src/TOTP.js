// --- Configuration ---
const SESS_COOKIE_NAME = '__totp_session';
const HASH_SALT = 'mil372Ixr6XY'; // !! 重要：请修改为一个复杂且唯一的盐值 !!
const PW_ITERATIONS = 100000; // 密码哈希迭代次数 (增加安全性, 100k 是一个更推荐的值)

// --- Base32 Decoder ---
const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32Lookup = Object.fromEntries(
  Array.from(base32Chars).map((c, i) => [c, i])
);

function base32Decode(encoded) {
  encoded = encoded.toUpperCase().replace(/=+$/, '');
  if (encoded.length === 0) return new Uint8Array(0);

  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(encoded.length * 5 / 8));

  for (let i = 0; i < encoded.length; i++) {
    const char = encoded[i];
    if (!(char in base32Lookup)) {
      throw new Error("Invalid Base32 character found: " + char);
    }
    value = (value << 5) | base32Lookup[char];
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output;
}

// --- TOTP Generation ---
async function generateTOTP(secretBase32, step = 30, digits = 6) {
  try {
    const secretBytes = base32Decode(secretBase32);
    const counter = Math.floor(Date.now() / 1000 / step);
    const counterBytes = new ArrayBuffer(8);
    const counterView = new DataView(counterBytes);

    // Set counter bytes in Big Endian format
    // Need to handle potential precision issues with large numbers in JS
    const high = Math.floor(counter / (2 ** 32));
    const low = counter % (2 ** 32);
    counterView.setUint32(0, high, false); // Big Endian
    counterView.setUint32(4, low, false);  // Big Endian

    const key = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const hmacResult = await crypto.subtle.sign(
      'HMAC',
      key,
      counterBytes
    );

    const hmacBytes = new Uint8Array(hmacResult);
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const code = (
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff)
    ) % (10 ** digits);

    return code.toString().padStart(digits, '0');
  } catch (error) {
    console.error("TOTP Generation Error:", error);
    return "错误";
  }
}

// --- Password Hashing (PBKDF2-SHA256) ---
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(HASH_SALT),
      iterations: PW_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 256 bits = 32 bytes
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

async function verifyPassword(storedHash, providedPassword) {
  const calculatedHash = await hashPassword(providedPassword);
  // Simple comparison (timing attacks are less of a concern for PBKDF2 hashes here, but constant-time compare is best practice if critical)
  return storedHash === calculatedHash;
}

// --- Database Initialization ---
async function initializeDatabase(db) {
  console.log("Initializing database...");
  try {
    // Check if tables exist (simple check by trying to query)
    try {
      await db.prepare("SELECT id FROM users LIMIT 1").first();
      await db.prepare("SELECT id FROM totp_keys LIMIT 1").first();
      console.log("Database tables already exist.");
      return true; // Tables likely exist
    } catch (e) {
      // Errors likely mean tables don't exist, proceed with creation
      console.log("Tables not found, creating...");
    }

    const batch = [
      db.prepare(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            `),
      db.prepare(`
                CREATE TABLE IF NOT EXISTS totp_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    remark TEXT NOT NULL,
                    secret TEXT NOT NULL, -- Store Base32 secret
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            `),
      // Add index for faster lookups
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_totp_keys_user_id ON totp_keys (user_id);`),
      db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);`)
    ];
    await db.batch(batch);
    console.log("Database tables created successfully.");
    return true;
  } catch (error) {
    console.error("Database initialization failed:", error);
    return false;
  }
}

// --- HTML Template Helper (PicoCSS Version) ---
function generateHTML(bodyContent, title = "TOTP 管理器", clientScript = "", user = null, loadJsQr = false) {
  // Helper function (server-side scope) for escaping data injected into HTML
  function escapeHtmlSrv(unsafe) {
    if (typeof unsafe !== 'string') {
      return unsafe == null ? '' : String(unsafe);
    }
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });
  }

  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtmlSrv(title)}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
    <style>
      /* Minimal custom styles needed */
      :root {
          --pico-font-size: 100%; /* Adjust base font size if needed */
          --message-display-zindex: 1050; /* Keep message z-index */
      }

      /* Center container for fixed-width content */
      body > .container {
        max-width: 800px; /* Adjust max width */
        margin: 1rem auto;
        padding: 1rem;
      }

      /* Message Styling (can use Pico alerts or custom like this) */
      .message-display {
          position: fixed;
          top: 1rem;
          left: 50%;
          transform: translateX(-50%);
          z-index: var(--message-display-zindex);
          width: auto;
          max-width: 90%; /* Relative max width */
          padding: 0.75rem 1.25rem;
          margin-bottom: 1rem;
          border: 1px solid transparent;
          border-radius: var(--pico-border-radius);
          opacity: 0; /* Start hidden for fade-in */
          transition: opacity 0.3s ease-in-out;
      }
      .message-display.show {
           opacity: 1;
      }
      .message-display.error-message {
          color: var(--pico-color-red-inverse);
          background-color: var(--pico-color-red);
          border-color: var(--pico-color-red-border);
      }
      .message-display.success-message {
          color: var(--pico-color-green-inverse);
          background-color: var(--pico-color-green);
          border-color: var(--pico-color-green-border);
      }

      /* Token Specific Styles */
      article.token-card { margin-bottom: 1rem; }
      article.token-card header { padding-bottom: 0.5rem; margin-bottom: 0.5rem; border-bottom: 1px solid var(--pico-muted-border-color); }
      article.token-card .token-value {
          font-size: 2em; /* Make token stand out */
          font-family: monospace;
          letter-spacing: 2px;
          color: var(--pico-primary);
          cursor: pointer;
          user-select: all; /* Allow easy selection */
          display: inline-block; /* Or block */
          margin-right: 1rem;
          word-break: break-all;
      }
       article.token-card .token-value:hover {
          text-decoration: underline;
       }

      article.token-card progress {
          width: 100px; /* Fixed width or relative */
          height: 10px;
          margin-top: 0.5rem; /* Space below token value */
          vertical-align: middle;
      }
       article.token-card progress[value]::-webkit-progress-value {
          background-color: var(--pico-primary); /* Default color */
          transition: background-color 0.3s ease;
      }
       article.token-card progress[value].low-time::-webkit-progress-value {
          background-color: var(--pico-color-red); /* Red when time is low */
       }
        /* Firefox specific */
        article.token-card progress[value]::-moz-progress-bar {
           background-color: var(--pico-primary);
           transition: background-color 0.3s ease;
        }
        article.token-card progress[value].low-time::-moz-progress-bar {
            background-color: var(--pico-color-red);
        }


      article.token-card footer { padding-top: 0.5rem; margin-top: 0.5rem; border-top: 1px solid var(--pico-muted-border-color); text-align: right; }
      article.token-card footer button { margin-left: 0.5rem; }

      /* Make token value and progress align better */
       .token-line {
           display: flex;
           align-items: center;
           flex-wrap: wrap; /* Wrap on small screens */
           gap: 1rem; /* Space between token and progress */
       }

       /* Manage Page Table Input */
        td input.remark-edit-input {
            margin: -0.5rem; /* Try to fill cell padding */
            width: calc(100% + 1rem); /* Adjust width considering negative margin */
            font-size: inherit; /* Use table font size */
        }

        /* QR Code Canvas Styling */
        #qr-canvas { max-width: 100%; height: auto; margin-top: 10px; border: 1px dashed var(--pico-muted-border-color); }

        /* Auth Tabs Alignment */
        #auth-tabs { margin-bottom: 1.5rem; }
        #auth-tabs .grid { grid-gap: 0.5rem; } /* Spacing between tab buttons */
        #auth-tabs button.outline { /* Style for active tab */
            /* Pico's outline buttons might serve as a good active indicator */
        }

        /* Responsive Table Wrapper */
        figure.table-wrapper { overflow-x: auto; margin-bottom: 1rem;}

        /* Make nav items align better */
        nav ul { padding: 0; margin: 0; list-style: none; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;}
        nav .user-info { margin-left: auto; display: flex; align-items: center; gap: 0.5rem;}
        nav .user-info form { margin: 0; display: inline-flex; } /* Align logout form correctly */

    </style>
</head>
<body>
    <main class="container">
        <header>
            <h1>${escapeHtmlSrv(title)}</h1>
            <nav>
                 <ul>
                    <li><a href="/">令牌展示</a></li>
                    <li><a href="/add">添加密钥</a></li>
                    <li><a href="/manage">管理密钥</a></li>
                 </ul>
                <div class="user-info">
                    ${user ? `<span>欢迎, ${escapeHtmlSrv(user.username)}</span><form action="/logout" method="post"><button type="submit" class="secondary outline">登出</button></form>` : '<a href="/login" role="button">登录/注册</a>'}
                    <button id="darkModeToggle" data-tooltip="切换主题" data-placement="bottom" class="outline secondary" style="width: auto; height: auto; padding: 0.3rem 0.5rem;">🌙</button>
                </div>
            </nav>
            <hr>
        </header>

        <div id="message-area"></div>

        ${bodyContent}

        <footer>
            <hr>
            <p style="text-align:center; font-size: 0.9em; color: var(--pico-muted-color);">
                TOTP 管理器运行在 Cloudflare Workers & D1. Powered by PicoCSS.
            </p>
        </footer>
    </main>

    <script>
        // --- Client-Side Utility ---
        function escapeHtml(unsafe) {
          if (typeof unsafe !== 'string') {
            return unsafe == null ? '' : String(unsafe);
          }
          const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
          return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });
        }

        function showMessage(text, type = 'success', duration = 5000) {
            const container = document.getElementById('message-area'); // Target the dedicated message area
            if (!container) return;

            // Remove any existing message first
            const existingMsg = container.querySelector('.message-display');
            if(existingMsg) existingMsg.remove();

            const msgDiv = document.createElement('div');
            msgDiv.className = type === 'error' ? 'error-message message-display' : 'success-message message-display';
            msgDiv.textContent = text;
            msgDiv.setAttribute('role', 'alert');
            container.prepend(msgDiv);

            // Fade in
            requestAnimationFrame(() => {
                msgDiv.classList.add('show');
            });

            if (duration > 0) {
                setTimeout(() => {
                    msgDiv.classList.remove('show');
                    // Remove after fade out transition completes (match transition duration)
                    setTimeout(() => msgDiv.remove(), 300);
                }, duration);
            }
        }

        function copyToClipboard(text) {
            if (!text || text === '------' || text === '错误') {
                showMessage('没有有效的令牌可复制', 'error');
                return;
            }
            navigator.clipboard.writeText(text).then(() => {
                showMessage('已复制到剪贴板!', 'success');
            }).catch(err => {
                console.error('Clipboard API error:', err);
                showMessage('复制失败，请手动复制。', 'error');
            });
        }

        // --- Dark Mode (PicoCSS Version) ---
        const darkModeToggle = document.getElementById('darkModeToggle');
        const htmlElement = document.documentElement;

        function applyDarkMode(isDark) {
            const theme = isDark ? 'dark' : 'light';
            htmlElement.setAttribute('data-theme', theme);
            darkModeToggle.textContent = isDark ? '☀️' : '🌙';
            try {
                 localStorage.setItem('theme', theme);
            } catch (e) { console.warn("LocalStorage not available for theme saving."); }
        }

        // Initial theme check
        let storedTheme = 'light'; // Default to light
        try {
            storedTheme = localStorage.getItem('theme');
        } catch(e) {}

        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');

        if (storedTheme === 'dark' || (storedTheme === null && prefersDark.matches)) {
            applyDarkMode(true);
        } else {
            applyDarkMode(false);
        }

        darkModeToggle.addEventListener('click', () => {
            const isDarkMode = htmlElement.getAttribute('data-theme') === 'dark';
            applyDarkMode(!isDarkMode);
        });

        // Listen for system theme changes if no preference is stored
         prefersDark.addEventListener('change', (e) => {
            try {
                // Only follow system if no manual override is set in localStorage
                 if (localStorage.getItem('theme') === null) {
                     applyDarkMode(e.matches);
                 }
            } catch(err){}
         });


        // --- Client-Side Script Placeholder ---
        ${clientScript}
    </script>
    ${
      loadJsQr ? '<script src="https://cdn.jsdelivr.net/npm/jsqr@1/dist/jsQR.min.js"><\/script>' : ''
  }
</body>
</html>
`;
}


// --- HTML Page Generators (PicoCSS Versions) ---

function loginRegisterPage(message = '', type = 'info', defaultTab = 'login') {
  // Server-side escape helper
  function escapeHtmlSrv(unsafe) { if(typeof unsafe !== 'string') { return unsafe == null ? '' : String(unsafe); } const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }; return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });}

  const body = `
        ${message ? `<article class="${type === 'error' ? 'error-message' : 'success-message'} message-display show" role="alert">${escapeHtmlSrv(message)}</article>` : ''}
        <div id="auth-tabs" style="margin-bottom: 1.5rem;">
            <div class="grid">
                <button onclick="showTab('login')" id="login-tab-btn" class="outline">登录</button>
                <button onclick="showTab('register')" id="register-tab-btn" class="outline">注册</button>
                <button onclick="showTab('temporary')" id="temporary-tab-btn" class="outline secondary">临时访问 (本地存储)</button>
            </div>
        </div>

        <section id="login-form" style="display: none;">
            <h2>用户登录</h2>
            <form action="/login" method="post">
                <label for="login-username">用户名:</label>
                <input type="text" id="login-username" name="username" required>

                <label for="login-password">密码:</label>
                <input type="password" id="login-password" name="password" required>

                <button type="submit">登录</button>
            </form>
        </section>

        <section id="register-form" style="display: none;">
            <h2>用户注册</h2>
            <form action="/register" method="post" id="registration-form">
                 <label for="reg-username">用户名:</label>
                 <input type="text" id="reg-username" name="username" required minlength="3">

                 <label for="reg-password">密码:</label>
                 <input type="password" id="reg-password" name="password" required minlength="6">

                 <label for="reg-password-confirm">确认密码:</label>
                 <input type="password" id="reg-password-confirm" name="password_confirm" required minlength="6">

                 <button type="submit">注册</button>
            </form>
        </section>

         <section id="temporary-access" style="display: none;">
             <h2>临时访问模式</h2>
             <article>
                 <p>在此模式下，您的 TOTP 密钥将仅存储在当前浏览器的本地存储 (LocalStorage) 中。</p>
                 <p><strong>重要:</strong></p>
                 <ul>
                     <li>密钥不会同步到服务器或其他设备。</li>
                     <li>清除浏览器数据将导致密钥丢失。</li>
                     <li>不建议在公共或共享计算机上使用此模式。</li>
                 </ul>
                 <footer>
                    <form action="/" method="get" style="display: inline;"><button type="submit" class="secondary">进入临时模式</button></form>
                    <small style="margin-left: 1rem;">已有账户? <a href="#login" onclick="showTab('login'); return false;">点此登录</a>.</small>
                 </footer>
             </article>
         </section>
    `;
  const script = `
        function showTab(tabId) {
            // Hide all tab content sections
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('register-form').style.display = 'none';
            document.getElementById('temporary-access').style.display = 'none';

            // Reset all tab buttons to default (outline)
             document.querySelectorAll('#auth-tabs button').forEach(btn => {
                btn.classList.add('outline'); // Ensure all are outline by default
                btn.classList.remove('secondary'); // Remove secondary if applied to temp button
                if (btn.id === 'temporary-tab-btn') btn.classList.add('secondary'); // Re-apply secondary to temp button
             });


            // Show the target section and make its button non-outline (active)
            const targetSection = document.getElementById(tabId + (tabId === 'temporary' ? '-access' : '-form'));
            if (targetSection) {
                targetSection.style.display = 'block';
            }
            const targetButton = document.getElementById(tabId + '-tab-btn');
            if (targetButton) {
                 targetButton.classList.remove('outline'); // Active tab is solid
            }
            // Optional: Update URL hash
            // window.location.hash = tabId;
        }

        // Client-side validation for registration form
        const regForm = document.getElementById('registration-form');
        if (regForm) {
            regForm.addEventListener('submit', function(event) {
                const username = document.getElementById('reg-username').value;
                const pwd = document.getElementById('reg-password').value;
                const confirmPwd = document.getElementById('reg-password-confirm').value;
                let errorMsg = '';

                if (username.length < 3) errorMsg = '用户名长度至少需要3位';
                else if (pwd.length < 6) errorMsg = '密码长度至少需要6位';
                else if (pwd !== confirmPwd) errorMsg = '两次输入的密码不一致';

                if (errorMsg) {
                    event.preventDefault(); // Stop submission
                    showMessage(errorMsg, 'error'); // Use the global showMessage
                }
            });
        }

        // Initial tab display logic
        const currentHash = window.location.hash.substring(1);
        const validTabs = ['login', 'register', 'temporary'];
        // Use defaultTab passed from server-side logic
        const initialTab = validTabs.includes(currentHash) ? currentHash : '${defaultTab}';
        showTab(initialTab); // Show the initial tab

        // If there's a message from the server, remove it after a delay
        const serverMsg = document.querySelector('.message-display[role="alert"]');
        if (serverMsg) {
            setTimeout(() => {
                serverMsg.classList.remove('show');
                setTimeout(() => serverMsg.remove(), 300);
            }, 5000); // Same duration as client-side messages
        }
    `;
  return generateHTML(body, "登录 / 注册", script, null, false); // No user, no QR scanner needed
}

function addKeyPage(user = null, message = '', type = 'info') {
  function escapeHtmlSrv(unsafe) { if(typeof unsafe !== 'string') { return unsafe == null ? '' : String(unsafe); } const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }; return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });}
  const body = `
        <h2>添加新的 TOTP 密钥</h2>
        ${message ? `<article class="${type === 'error' ? 'error-message' : 'success-message'} message-display show" role="alert">${escapeHtmlSrv(message)}</article>` : ''}

        <form id="add-key-form">
            <label for="remark">备注 (例如: Google, GitHub):</label>
            <input type="text" id="remark" name="remark" required>

            <label for="secret">密钥 (Base32 格式) 或 otpauth:// URI:</label>
            <input type="text" id="secret" name="secret" placeholder="输入 Base32 密钥或粘贴 URI" required aria-describedby="secret-help">
            <small id="secret-help">例如: JBSWY3DPEHPK3PXP 或 otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example</small>

            <p style="text-align: center; margin: 1.5rem 0;">— 或 —</p>

            <label for="qr-code-file">上传二维码图片:</label>
            <input type="file" id="qr-code-file" accept="image/*">
            <canvas id="qr-canvas" style="display: none;"></canvas>

            <button type="submit" style="margin-top: 1rem;">添加密钥</button>
            ${user ? '' : '<p><small>注意：您当前未登录，密钥将保存在浏览器本地存储中。</small></p>'}
        </form>
    `;
  const script = `
        const addForm = document.getElementById('add-key-form');
        const remarkInput = document.getElementById('remark');
        const secretInput = document.getElementById('secret');
        const qrCodeInput = document.getElementById('qr-code-file');
        const qrCanvas = document.getElementById('qr-canvas');
        const ctx = qrCanvas.getContext('2d', { willReadFrequently: true });

        function parseOtpAuthUri(uri) {
            try {
                const url = new URL(uri);
                if (url.protocol !== 'otpauth:') return null;
                if (url.host !== 'totp') {
                    showMessage('只支持 TOTP 类型 (otpauth://totp/...)', 'error');
                    return null;
                }

                const pathParts = url.pathname.substring(1).split(':');
                const issuerFromPath = pathParts.length > 1 ? decodeURIComponent(pathParts[0].replace(/\\/+/g, ' ')) : null;
                const account = decodeURIComponent(pathParts[pathParts.length - 1].replace(/\\/+/g, ' '));

                const params = url.searchParams;
                const secret = params.get('secret');
                const issuerParam = params.get('issuer');
                const issuer = issuerParam ? decodeURIComponent(issuerParam.replace(/\\/+/g, ' ')) : issuerFromPath;

                if (!secret) return null;

                // Simple Base32 check (may need refinement)
                const cleanedSecret = secret.toUpperCase().replace(/\\s+/g, '');
                if (!/^[A-Z2-7]+=*$/.test(cleanedSecret) || cleanedSecret.length < 8) {
                     showMessage('URI 中的 Secret 无效或不是 Base32 格式。', 'error');
                     return null;
                }


                if ((params.get('algorithm') || 'SHA1').toUpperCase() !== 'SHA1') console.warn('仅保证支持 SHA1 算法');
                if (params.get('digits') && params.get('digits') !== '6') console.warn('仅保证支持 6 位数');
                if (params.get('period') && params.get('period') !== '30') console.warn('仅保证支持 30 秒步进');

                let remark = '';
                if (issuer) {
                    remark = issuer;
                    if (account && account !== issuer) remark += \` (\${account})\`;
                } else if (account) {
                    remark = account;
                } else {
                    remark = '未命名密钥';
                }

                return { secret: cleanedSecret, remark: remark.trim() };
            } catch (e) {
                console.error("Error parsing OTPAuth URI:", e);
                showMessage('无法解析提供的 URI，请检查格式。', 'error');
                return null;
            }
        }

        secretInput.addEventListener('input', (event) => {
            const value = event.target.value.trim();
            if (value.toLowerCase().startsWith('otpauth://')) {
                const parsed = parseOtpAuthUri(value);
                if (parsed) {
                    secretInput.value = parsed.secret; // Update input with only the secret
                    if (!remarkInput.value.trim()) { // Only fill remark if it's empty
                        remarkInput.value = parsed.remark;
                    }
                    showMessage('已从 URI 中提取密钥和备注。', 'success', 3000);
                } else {
                   // Parsing failed, message shown in parseOtpAuthUri
                   // Maybe clear the input or leave it as is? Let's leave it for now.
                }
            }
        });

        qrCodeInput.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (!file || typeof jsQR === 'undefined') {
                if (typeof jsQR === 'undefined') showMessage('QR 扫描库 (jsQR) 未加载。', 'error');
                return;
            }

            const reader = new FileReader();
            reader.onload = function(e) {
                const img = new Image();
                img.onload = function() {
                    qrCanvas.style.display = 'block';
                    const maxWidth = qrCanvas.parentElement.clientWidth || 300;
                    const scale = Math.min(1, maxWidth / img.width);
                    qrCanvas.width = img.width;
                    qrCanvas.height = img.height;
                    ctx.drawImage(img, 0, 0, img.width, img.height);
                    qrCanvas.style.width = (img.width * scale) + 'px'; // Scale visually
                    qrCanvas.style.height = (img.height * scale) + 'px';

                    try {
                        const imageData = ctx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
                        const code = jsQR(imageData.data, imageData.width, imageData.height, {
                            inversionAttempts: "dontInvert",
                        });

                        if (code && code.data) {
                            console.log("QR Code Data:", code.data);
                            if (code.data.toLowerCase().startsWith('otpauth://')) {
                                const parsed = parseOtpAuthUri(code.data);
                                if (parsed) {
                                    secretInput.value = parsed.secret;
                                    if (!remarkInput.value.trim()) {
                                        remarkInput.value = parsed.remark;
                                    }
                                    showMessage('成功从二维码中提取密钥。', 'success');
                                } // parseOtpAuthUri handles its own errors
                            } else {
                                const potentialSecret = code.data.trim().toUpperCase().replace(/\\s+/g, '');
                                if (/^[A-Z2-7]+=*$/.test(potentialSecret) && potentialSecret.length >= 8) {
                                    secretInput.value = potentialSecret;
                                    showMessage('从二维码读取到疑似Base32密钥，请填写备注。', 'success');
                                } else {
                                    showMessage('二维码内容不是有效的 otpauth:// URI 或 Base32 密钥。', 'error');
                                }
                            }
                        } else {
                            showMessage('未在图片中检测到二维码或无法解码。', 'error');
                        }
                    } catch (qrError) {
                        console.error("jsQR Error:", qrError);
                        showMessage('扫描二维码时出错: ' + qrError.message, 'error');
                    }
                }
                img.onerror = function() { showMessage('无法加载图片文件。', 'error'); }
                img.src = e.target.result;
            }
            reader.onerror = function() { showMessage('读取文件时出错。', 'error'); }
            reader.readAsDataURL(file);
            event.target.value = ''; // Clear file input
        });


        addForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const remark = remarkInput.value.trim();
            let secret = secretInput.value.trim().toUpperCase().replace(/\\s+/g, ''); // Clean secret

            const base32Regex = /^[A-Z2-7]+=*$/;
            if (!remark) {
                showMessage('备注不能为空。', 'error'); return;
            }
            if (!base32Regex.test(secret) || secret.length < 8) {
                showMessage('密钥格式无效。请输入有效的 Base32 编码密钥 (至少8个字符)。', 'error');
                return;
            }

            const keyData = { remark, secret };
            const isUserLoggedIn = ${user ? 'true' : 'false'};

            // Disable button during submission
            const submitButton = addForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.setAttribute('aria-busy', 'true');


            if (isUserLoggedIn) {
                // Logged-in user: Send to server API
                try {
                    const response = await fetch('/api/keys', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                        body: JSON.stringify(keyData)
                    });
                    if (response.ok) {
                        showMessage('密钥添加成功！正在跳转...', 'success', 2000);
                        setTimeout(() => window.location.href = '/', 2000);
                    } else {
                        const result = await response.json().catch(() => ({ error: '添加失败，无法解析响应' }));
                        showMessage('添加失败: ' + (result.error || response.statusText || '未知错误'), 'error');
                        submitButton.disabled = false;
                        submitButton.removeAttribute('aria-busy');
                    }
                } catch (error) {
                    console.error("Error adding key via API:", error);
                    showMessage('添加密钥时发生网络错误。', 'error');
                    submitButton.disabled = false;
                    submitButton.removeAttribute('aria-busy');
                }
            } else {
                // Temporary user: Save to LocalStorage
                try {
                    let localKeys = JSON.parse(localStorage.getItem('temp_totp_keys') || '[]');
                    if (localKeys.some(key => key.remark.toLowerCase() === remark.toLowerCase())) {
                         if (!confirm(\`已存在备注为 "\${remark}" 的本地密钥，确定要重复添加吗？\`)) {
                             submitButton.disabled = false;
                             submitButton.removeAttribute('aria-busy');
                             return;
                         }
                    }
                    keyData.id = 'local_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
                    localKeys.push(keyData);
                    localStorage.setItem('temp_totp_keys', JSON.stringify(localKeys));
                    showMessage('密钥已保存到浏览器本地存储。正在跳转...', 'success', 2000);
                    addForm.reset(); // Clear form
                    qrCanvas.style.display = 'none'; // Hide canvas
                    setTimeout(() => window.location.href = '/', 2000);
                } catch (e) {
                    console.error("Error saving to LocalStorage:", e);
                    showMessage('保存到本地存储时出错: ' + e.message, 'error');
                    submitButton.disabled = false;
                    submitButton.removeAttribute('aria-busy');
                }
            }
        });

        // If there's a server message, handle its display/removal
        const serverMsgAdd = document.querySelector('.message-display[role="alert"]');
        if (serverMsgAdd) {
            setTimeout(() => {
                 serverMsgAdd.classList.remove('show');
                 setTimeout(() => serverMsgAdd.remove(), 300);
             }, 5000);
        }
    `;
  return generateHTML(body, "添加新的 TOTP 密钥", script, user, true); // Need jsQR
}

function manageKeysPage(keys = [], user = null, message = '', type = 'info') {
  function escapeHtmlSrv(unsafe) { if(typeof unsafe !== 'string') { return unsafe == null ? '' : String(unsafe); } const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }; return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });}
  let tableRows = '';
  if (user && keys && keys.length > 0) {
    keys.forEach(key => {
      const escapedRemark = escapeHtmlSrv(key.remark);
      const escapedSecret = escapeHtmlSrv(key.secret);
      const escapedId = escapeHtmlSrv(String(key.id));
      const escapedRemarkJS = escapedRemark.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');

      tableRows += `
                <tr id="key-row-${escapedId}">
                    <td data-label="备注">
                        <input type="text" value="${escapedRemark}" id="remark-input-${escapedId}" class="remark-edit-input" aria-label="备注编辑框" />
                    </td>
                    <td data-label="密钥 (Base32)"><code>${escapedSecret}</code></td>
                    <td data-label="操作">
                        <button class="secondary outline" onclick="updateKey('${escapedId}')">更新</button>
                        <button class="contrast outline" onclick="confirmDeleteKey('${escapedId}', '${escapedRemarkJS}')">删除</button>
                    </td>
                </tr>`;
    });
  } else if (user && (!keys || keys.length === 0)) {
    tableRows = '<tr><td colspan="3">您还没有添加任何密钥。 <a href="/add">立即添加</a></td></tr>';
  }

  const body = `
        <h2>管理 TOTP 密钥</h2>
        ${message ? `<article class="${type === 'error' ? 'error-message' : 'success-message'} message-display show" role="alert">${escapeHtmlSrv(message)}</article>` : ''}
        ${user ? '' : '<p><small>注意：您当前处于临时模式，以下密钥存储在浏览器本地存储中。</small></p>'}

        <figure class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>备注</th>
                    <th>密钥 (Base32)</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="manage-keys-tbody">
                ${tableRows}
                <template id="key-row-template">
                     <tr>
                         <td data-label="备注"><input type="text" value="" class="remark-edit-input" aria-label="备注编辑框" /></td>
                         <td data-label="密钥 (Base32)"><code></code></td>
                         <td data-label="操作">
                             <button class="secondary outline">更新</button>
                             <button class="contrast outline">删除</button>
                         </td>
                     </tr>
                 </template>
                 <template id="no-keys-row-template">
                     <tr><td colspan="3">没有找到密钥。 <a href="/add">立即添加</a></td></tr>
                 </template>
            </tbody>
        </table>
        </figure>
    `;

  const script = `
        const isUserLoggedIn_Manage = ${user ? 'true' : 'false'};
        const tbody = document.getElementById('manage-keys-tbody');
        const rowTemplate = document.getElementById('key-row-template');
        const noKeysTemplate = document.getElementById('no-keys-row-template');

        // --- Client-Side Key Management Logic ---

        function renderManageTableRow(key) {
            const safeId = escapeHtml(String(key.id));
            const safeRemark = escapeHtml(key.remark);
            const safeSecret = escapeHtml(key.secret);
            const escapedRemarkForJS = safeRemark.replace(/\\'/g, "\\\\'").replace(/\"/g, '\\"');

            const clone = rowTemplate.content.cloneNode(true);
            const tr = clone.querySelector('tr');
            const cells = tr.querySelectorAll('td');
            const remarkInput = cells[0].querySelector('input');
            const secretCell = cells[1].querySelector('code'); // Target code element
            const updateButton = cells[2].querySelector('button.secondary');
            const deleteButton = cells[2].querySelector('button.contrast'); // Use contrast for delete

            tr.id = 'key-row-' + safeId;
            remarkInput.value = safeRemark;
            remarkInput.id = 'remark-input-' + safeId;
            remarkInput.defaultValue = safeRemark; // Store original for revert
            secretCell.textContent = safeSecret; // Set secret in code tag

            updateButton.onclick = () => updateKey(safeId);
            deleteButton.onclick = () => confirmDeleteKey(safeId, escapedRemarkForJS);

            return clone;
        }

        function loadTemporaryKeysForManage() {
            if (!isUserLoggedIn_Manage) {
                tbody.innerHTML = ''; // Clear existing rows (keep templates)
                try {
                    const localKeys = JSON.parse(localStorage.getItem('temp_totp_keys') || '[]');
                    if (localKeys.length > 0) {
                        localKeys.sort((a, b) => a.remark.localeCompare(b.remark));
                        localKeys.forEach(key => {
                            tbody.appendChild(renderManageTableRow(key));
                        });
                    } else {
                        tbody.appendChild(noKeysTemplate.content.cloneNode(true));
                    }
                } catch (e) {
                    console.error("Error loading temporary keys for manage page:", e);
                     tbody.innerHTML = '<tr><td colspan="3"><article role="alert" class="error">加载本地密钥时出错。</article></td></tr>';
                 }
             } else if (tbody.children.length === 0 && !tbody.querySelector('tr')) {
                 // If logged in but server rendered nothing (maybe JS error prevented server render)
                 tbody.appendChild(noKeysTemplate.content.cloneNode(true));
             }
        }

        async function updateKey(keyId) {
            const remarkInput = document.getElementById('remark-input-' + keyId);
            if (!remarkInput) return;
            const originalRemark = remarkInput.defaultValue;
            const newRemark = remarkInput.value.trim();
            const updateButton = remarkInput.closest('tr').querySelector('button.secondary');

            if (!newRemark) {
                showMessage('备注不能为空。', 'error');
                remarkInput.value = originalRemark; // Revert
                return;
            }

            updateButton.disabled = true;
            updateButton.setAttribute('aria-busy', 'true');

            if (isUserLoggedIn_Manage) {
                // Logged-in user: Use API
                try {
                    const response = await fetch('/api/keys/' + keyId, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                        body: JSON.stringify({ remark: newRemark })
                    });
                    if (response.ok) {
                        const safeNewRemark = escapeHtml(newRemark);
                        showMessage('备注更新成功！', 'success');
                        remarkInput.value = safeNewRemark;
                        remarkInput.defaultValue = safeNewRemark; // Update default value
                         // Update delete confirmation prompt data
                        const deleteButton = remarkInput.closest('tr').querySelector('button.contrast');
                        if (deleteButton) {
                            const escapedRemarkJS = safeNewRemark.replace(/\\'/g, "\\\\'").replace(/\"/g, '\\"');
                            deleteButton.onclick = () => confirmDeleteKey(keyId, escapedRemarkJS);
                        }
                    } else {
                        const result = await response.json().catch(() => ({}));
                        showMessage('更新失败: ' + (result.error || response.statusText || '未知API错误'), 'error');
                        remarkInput.value = originalRemark; // Revert on error
                    }
                } catch (error) {
                    console.error("Error updating key via API:", error);
                    showMessage('更新密钥时发生网络错误。', 'error');
                    remarkInput.value = originalRemark; // Revert on error
                } finally {
                    updateButton.disabled = false;
                    updateButton.removeAttribute('aria-busy');
                }
            } else {
                // Temporary user: Update LocalStorage
                try {
                    let localKeys = JSON.parse(localStorage.getItem('temp_totp_keys') || '[]');
                    const keyIndex = localKeys.findIndex(k => String(k.id) === keyId);
                    if (keyIndex > -1) {
                        localKeys[keyIndex].remark = newRemark;
                        localStorage.setItem('temp_totp_keys', JSON.stringify(localKeys));
                        const safeNewRemark = escapeHtml(newRemark);
                        showMessage('备注已在本地更新。', 'success');
                        remarkInput.value = safeNewRemark;
                        remarkInput.defaultValue = safeNewRemark;
                        // Update delete confirmation prompt data
                         const deleteButton = remarkInput.closest('tr').querySelector('button.contrast');
                         if (deleteButton) {
                             const escapedRemarkJS = safeNewRemark.replace(/\\'/g, "\\\\'").replace(/\"/g, '\\"');
                             deleteButton.onclick = () => confirmDeleteKey(keyId, escapedRemarkJS);
                         }
                    } else {
                        showMessage('未找到要更新的本地密钥。', 'error');
                        remarkInput.value = originalRemark;
                    }
                } catch (e) {
                    console.error("Error updating local key:", e);
                    showMessage('本地更新备注时出错: ' + e.message, 'error');
                    remarkInput.value = originalRemark;
                } finally {
                     updateButton.disabled = false;
                     updateButton.removeAttribute('aria-busy');
                 }
            }
        }

        function confirmDeleteKey(keyId, keyRemark) {
            // keyRemark is JS-escaped, unescape for display in confirm dialog
            const unescapedRemark = keyRemark.replace(/\\'/g, "\\\\'").replace(/\"/g, '\\"');
            if (confirm(\`您确定要删除密钥 "\${unescapedRemark}" 吗？此操作无法撤销。\`)) {
                deleteKey(keyId);
            }
        }

        async function deleteKey(keyId) {
             const row = document.getElementById('key-row-' + keyId);
             const deleteButton = row ? row.querySelector('button.contrast') : null;
             if (deleteButton) {
                 deleteButton.disabled = true;
                 deleteButton.setAttribute('aria-busy', 'true');
             }

            if (isUserLoggedIn_Manage) {
                // Logged-in user: Use API
                try {
                    const response = await fetch('/api/keys/' + keyId, { method: 'DELETE' });
                    if (response.ok || response.status === 204) {
                        showMessage('密钥删除成功！', 'success');
                        row?.remove();
                        if (tbody.children.length === 0 || (tbody.children.length === 1 && tbody.children[0].matches('template'))) { // Check if only templates remain
                            tbody.appendChild(noKeysTemplate.content.cloneNode(true));
                        }
                    } else {
                        const result = await response.json().catch(() => ({}));
                        showMessage('删除失败: ' + (result.error || response.statusText || '未知API错误'), 'error');
                         if (deleteButton) {
                             deleteButton.disabled = false;
                             deleteButton.removeAttribute('aria-busy');
                         }
                    }
                } catch (error) {
                    console.error("Error deleting key via API:", error);
                    showMessage('删除密钥时发生网络错误。', 'error');
                     if (deleteButton) {
                         deleteButton.disabled = false;
                         deleteButton.removeAttribute('aria-busy');
                     }
                }
            } else {
                // Temporary user: Update LocalStorage
                try {
                    let localKeys = JSON.parse(localStorage.getItem('temp_totp_keys') || '[]');
                    const initialLength = localKeys.length;
                    localKeys = localKeys.filter(k => String(k.id) !== keyId);
                    if (localKeys.length < initialLength) {
                        localStorage.setItem('temp_totp_keys', JSON.stringify(localKeys));
                        showMessage('密钥已从本地存储删除。', 'success');
                        row?.remove();
                         if (tbody.children.length === 0 || (tbody.children.length === 1 && tbody.children[0].matches('template'))) {
                            tbody.appendChild(noKeysTemplate.content.cloneNode(true));
                        }
                    } else {
                        showMessage('未找到要删除的本地密钥。', 'error');
                    }
                } catch (e) {
                    console.error("Error deleting local key:", e);
                    showMessage('本地删除密钥时出错: ' + e.message, 'error');
                } finally {
                     if (deleteButton) {
                         deleteButton.disabled = false;
                         deleteButton.removeAttribute('aria-busy');
                     }
                 }
            }
        }

        // Initial population if temporary mode
        loadTemporaryKeysForManage();

        // Handle server message display/removal
        const serverMsgManage = document.querySelector('.message-display[role="alert"]');
        if (serverMsgManage) {
             setTimeout(() => {
                 serverMsgManage.classList.remove('show');
                 setTimeout(() => serverMsgManage.remove(), 300);
             }, 5000);
        }
    `;
  return generateHTML(body, "管理 TOTP 密钥", script, user, false);
}

function displayTokensPage(keys = [], user = null) {
  function escapeHtmlSrv(unsafe) { if(typeof unsafe !== 'string') { return unsafe == null ? '' : String(unsafe); } const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }; return unsafe.replace(/[&<>"']/g, function(m) { return map[m]; });}
  let keyCards = '';
  if (user && keys && keys.length > 0) {
    keys.forEach(key => {
      const safeId = `token-${escapeHtmlSrv(String(key.id))}`;
      const escapedRemark = escapeHtmlSrv(key.remark);
      // Secret is not rendered directly, but stored in data attribute later

      keyCards += `
                  <article class="token-card" id="${safeId}-card">
                      <header>
                          <strong>${escapedRemark}</strong>
                      </header>
                      <div class="token-line">
                          <span class="token-value" id="${safeId}-value" data-secret="${escapeHtmlSrv(key.secret)}" onclick="copyToClipboard(this.textContent)" title="点击复制">------</span>
                          <progress id="${safeId}-progress" value="0" max="30"></progress>
                      </div>
                      <footer>
                           <button class="secondary outline" onclick="location.href='/manage#key-row-${escapeHtmlSrv(String(key.id))}'">管理</button>
                           <button class="outline" onclick="copyToClipboard(document.getElementById('${safeId}-value').textContent)">复制</button>
                       </footer>
                  </article>`;
    });
  } else if (user && (!keys || keys.length === 0)) {
    keyCards = `
              <article>
                  <p>您还没有添加任何 TOTP 密钥。</p>
                  <footer><a href="/add" role="button">立即添加一个？</a></footer>
               </article>`;
  }
  // Note: Temporary user keys are loaded client-side only

  const body = `
        <h2>当前 TOTP 令牌</h2>
         ${user ? '' : '<p><small>注意：您当前处于临时模式，密钥存储在浏览器本地存储中。 <a href="/login">登录/注册</a> 以同步。</small></p>'}
        <div id="token-list">
            ${keyCards}
            <template id="token-card-template">
                <article class="token-card">
                    <header>
                        <strong class="token-remark"></strong>
                    </header>
                     <div class="token-line">
                         <span class="token-value" data-secret="" onclick="copyToClipboard(this.textContent)" title="点击复制">------</span>
                         <progress value="0" max="30"></progress>
                     </div>
                     <footer>
                         <button class="secondary outline">管理</button>
                         <button class="outline">复制</button>
                     </footer>
                </article>
            </template>
            <template id="no-tokens-template">
                <article id="no-tokens-message">
                     <p>您还没有添加任何 TOTP 密钥。</p>
                     <footer>
                        <a href="/add" role="button">立即添加一个？</a>
                        ${user ? '' : '<small style="margin-left: 1rem;">或 <a href="/login">登录/注册</a> 以使用云同步。</small>'}
                     </footer>
                 </article>
             </template>
        </div>
    `;

  const script = `
        const isUserLoggedIn_Display = ${user ? 'true' : 'false'};
        const tokenListDiv = document.getElementById('token-list');
        const cardTemplate = document.getElementById('token-card-template');
        const noTokensTemplate = document.getElementById('no-tokens-template');

        // --- Client-Side TOTP Generation (Assume available from worker scope) ---
        const base32Chars_client = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const base32Lookup_client = Object.fromEntries(
          Array.from(base32Chars_client).map((c, i) => [c, i])
        );

        function base32Decode_client(encoded) { /* ... same as worker scope ... */
            encoded = encoded.toUpperCase().replace(/=+$/, '');
            if (encoded.length === 0) return new Uint8Array(0);
            let bits = 0, value = 0, index = 0;
            const output = new Uint8Array(Math.floor(encoded.length * 5 / 8));
            for (let i = 0; i < encoded.length; i++) {
              const char = encoded[i];
              if (!(char in base32Lookup_client)) throw new Error("Invalid Base32 char: " + char);
              value = (value << 5) | base32Lookup_client[char];
              bits += 5;
              if (bits >= 8) {
                output[index++] = (value >>> (bits - 8)) & 0xFF;
                bits -= 8;
              }
            }
            return output;
        }

        async function generateTOTP_client(secretBase32, step = 30, digits = 6) { /* ... same as worker scope ... */
             try {
                 if (!crypto.subtle) return "错误: Crypto不支持";
                 const secretBytes = base32Decode_client(secretBase32);
                 const counter = Math.floor(Date.now() / 1000 / step);
                 const counterBytes = new ArrayBuffer(8);
                 const counterView = new DataView(counterBytes);
                 const high = Math.floor(counter / (2 ** 32));
                 const low = counter % (2 ** 32);
                 counterView.setUint32(0, high, false);
                 counterView.setUint32(4, low, false);

                 const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
                 const hmacResult = await crypto.subtle.sign('HMAC', key, counterBytes);
                 const hmacBytes = new Uint8Array(hmacResult);
                 const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
                 const code = (
                     ((hmacBytes[offset] & 0x7f) << 24) |
                     ((hmacBytes[offset + 1] & 0xff) << 16) |
                     ((hmacBytes[offset + 2] & 0xff) << 8) |
                     (hmacBytes[offset + 3] & 0xff)
                 ) % (10 ** digits);
                 return code.toString().padStart(digits, '0');
             } catch (error) {
                 console.error("Client TOTP Error:", error, "Secret:", secretBase32 ? secretBase32.substring(0,4)+"..." : "N/A");
                 return "错误";
             }
         }

        // --- Token Update & Display Logic ---
        const step = 30; // TOTP step duration
        let intervalId = null;

        function createTokenCardDOM(key) {
            const safeId = 'token-' + escapeHtml(String(key.id));
            const safeRemark = escapeHtml(key.remark);
            const safeSecret = escapeHtml(key.secret); // Store escaped secret in data attribute

            const clone = cardTemplate.content.cloneNode(true);
            const card = clone.querySelector('.token-card');
            const remarkEl = clone.querySelector('.token-remark');
            const valueEl = clone.querySelector('.token-value');
            const progressEl = clone.querySelector('progress');
            const manageBtn = clone.querySelector('button.secondary');
            const copyBtn = clone.querySelector('footer button:not(.secondary)'); // More specific selector

            card.id = safeId + '-card';
            remarkEl.textContent = safeRemark;
            valueEl.id = safeId + '-value';
            valueEl.dataset.secret = key.secret; // Store RAW secret here for generation
            progressEl.id = safeId + '-progress';
            progressEl.max = step; // Set max for progress bar

            manageBtn.onclick = () => location.href='/manage#key-row-' + escapeHtml(String(key.id));
            copyBtn.onclick = () => copyToClipboard(valueEl.textContent);

            return clone;
        }

        async function updateTokens() {
            const tokenValueElements = tokenListDiv.querySelectorAll('.token-value');
            if (tokenValueElements.length === 0) {
                if (intervalId) clearInterval(intervalId);
                intervalId = null;
                return; // No tokens to update
            }

            const now = Date.now() / 1000;
            const secondsIntoStep = now % step;
            const secondsRemaining = step - secondsIntoStep;

            for (const el of tokenValueElements) {
                const secret = el.getAttribute('data-secret'); // Get raw secret
                const progressEl = document.getElementById(el.id.replace('-value', '-progress'));

                // Update token value only near the beginning of the step or if it's currently invalid/placeholder
                if (secondsIntoStep < 1.5 || ['------', '错误'].includes(el.textContent)) {
                    if (secret) { // Ensure secret exists
                       const totp = await generateTOTP_client(secret, step, 6);
                       // Only update DOM if value changes to prevent unnecessary redraws/selection clear
                       if (el.textContent !== totp) {
                          el.textContent = totp;
                       }
                    } else {
                        el.textContent = '密钥丢失'; // Should not happen with proper loading
                    }
                }

                // Update progress bar
                if (progressEl) {
                    progressEl.value = Math.floor(secondsRemaining); // Set value to remaining seconds
                     // Add class for styling when time is low (e.g., last 5 seconds)
                     if (secondsRemaining <= 5) {
                        progressEl.classList.add('low-time');
                     } else {
                        progressEl.classList.remove('low-time');
                     }
                }
            }
        }

        function initializeTokenDisplay() {
            // Clear only dynamically added cards, keeping templates and server-rendered ones if logged in.
            tokenListDiv.querySelectorAll('.token-card:not([id^="token-"])').forEach(el => el.remove()); // Remove old client-side cards if any
             const existingNoTokens = tokenListDiv.querySelector('#no-tokens-message');
             if(existingNoTokens) existingNoTokens.remove();


            if (isUserLoggedIn_Display) {
                // Server should have rendered cards in 'keyCards' variable injected into the body.
                // If there are no cards rendered by the server AND no client-side cards exist, show "no tokens".
                if (tokenListDiv.querySelectorAll('.token-card').length === 0) {
                     tokenListDiv.prepend(noTokensTemplate.content.cloneNode(true));
                 }

            } else {
                // Temporary user: Load from LocalStorage
                try {
                    const localKeys = JSON.parse(localStorage.getItem('temp_totp_keys') || '[]');
                     // Clear any server-side placeholder (like the "add a key" message) if local keys exist
                    const serverPlaceholder = tokenListDiv.querySelector('article:not(.token-card)');
                    if(localKeys.length > 0 && serverPlaceholder) serverPlaceholder.remove();

                    if (localKeys.length > 0) {
                        localKeys.sort((a, b) => a.remark.localeCompare(b.remark));
                        localKeys.forEach(key => {
                            // Prepend to keep order consistent with templates at the end
                            tokenListDiv.prepend(createTokenCardDOM(key));
                        });
                    } else if (tokenListDiv.querySelectorAll('.token-card').length === 0) {
                        // Show no-tokens message only if no server cards exist either
                        tokenListDiv.prepend(noTokensTemplate.content.cloneNode(true));
                    }
                } catch (e) {
                    console.error("Error loading temp keys for display:", e);
                     tokenListDiv.innerHTML = '<article role="alert" class="error">加载本地存储的密钥时出错。</article>';
                 }
            }

            // Start update loop ONLY if there are token elements present
            if (tokenListDiv.querySelector('.token-value')) {
                updateTokens(); // Initial update immediately
                if (!intervalId) {
                    intervalId = setInterval(updateTokens, 1000); // Update every second
                }
            } else {
                if (intervalId) clearInterval(intervalId); // Stop if no tokens
                intervalId = null;
            }
        }

        // Initialize the display on page load
        initializeTokenDisplay();
    `;
  return generateHTML(body, "TOTP 令牌", script, user, false); // QR scanner not needed here
}


// --- Utility Functions ---
function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
    const [key, ...valueParts] = cookie.split('='); // Handle potential '=' in value
    const value = valueParts.join('=').trim();
    if (key) acc[key.trim()] = value;
    return acc;
  }, {});
  return cookies[name] || null;
}

// Helper to create redirect responses with messages
function redirectWithMessage(url, message, type = 'info', status = 302, hash = '') {
  const redirectUrl = new URL(url);
  redirectUrl.searchParams.set('message', message);
  redirectUrl.searchParams.set('type', type);
  redirectUrl.hash = hash; // Add hash for targeting tabs/sections
  return Response.redirect(redirectUrl.toString(), status);
}


// --- Request Handler ---
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const db = env.DATABASE; // D1 Binding

    // --- Database Initialization Check ---
    // Run this check early, maybe only on first request or specific paths if performance is critical
    try {
      await db.prepare("SELECT 1 FROM users LIMIT 1").first();
    } catch (e) {
      console.warn("DB Check: Users table query failed, attempting init.", e.message);
      const initOk = await initializeDatabase(db);
      if (!initOk) {
        // Use generateHTML to show a user-friendly error page
        const errorBody = `<article role="alert"><h2>数据库错误</h2><p>无法初始化数据库。请检查 Cloudflare Worker 日志和 D1 配置。</p></article>`;
        return new Response(generateHTML(errorBody, "数据库错误"), { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
    }

    // --- User Authentication ---
    let user = null;
    const sessionId = getCookie(request, SESS_COOKIE_NAME);
    if (sessionId) {
      // **INSECURE**: Using username as session ID. Replace with secure session management!
      // Consider using crypto.randomUUID() for session IDs stored in KV or D1 with expiry.
      try {
        const userRecord = await db.prepare("SELECT id, username FROM users WHERE username = ?1")
          .bind(sessionId)
          .first();
        if (userRecord) {
          user = { id: userRecord.id, username: userRecord.username };
        } else {
          console.log(`Invalid session ID cookie found: ${sessionId}. Clearing cookie and redirecting.`);
          const logoutHeaders = new Headers({
            'Location': '/login?message=' + encodeURIComponent('会话无效，请重新登录') + '&type=error',
            // Clear the cookie
            'Set-Cookie': `${SESS_COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax${url.protocol === 'https:' ? '; Secure' : ''}`
          });
          return new Response(null, { status: 302, headers: logoutHeaders });
        }
      } catch (dbError) {
        console.error("Session DB Error:", dbError);
        // Don't block the request, just log the error. User remains null.
      }
    }

    // --- API Endpoints (require logged-in user) ---
    if (path.startsWith('/api/')) {
      if (!user) {
        return new Response(JSON.stringify({ error: "需要登录" }), { status: 401, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
      }

      // GET /api/keys
      if (path === '/api/keys' && method === 'GET') {
        try {
          const { results } = await db.prepare("SELECT id, remark, secret FROM totp_keys WHERE user_id = ?1 ORDER BY remark")
            .bind(user.id)
            .all();
          return new Response(JSON.stringify(results || []), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        } catch (e) {
          console.error("API GET Keys Error:", e);
          return new Response(JSON.stringify({ error: "获取密钥列表失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        }
      }
      // POST /api/keys
      if (path === '/api/keys' && method === 'POST') {
        try {
          const { remark, secret } = await request.json();
          if (!remark || !secret) return new Response(JSON.stringify({ error: "备注和密钥不能为空" }), { status: 400, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

          const cleanedSecret = secret.toUpperCase().replace(/\s+/g, '');
          const base32Regex = /^[A-Z2-7]+=*$/;
          if (!base32Regex.test(cleanedSecret) || cleanedSecret.length < 8) return new Response(JSON.stringify({ error: "密钥格式无效" }), { status: 400, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

          // Optional: Validate if the secret can generate a TOTP
          const testOtp = await generateTOTP(cleanedSecret);
          if (testOtp === "错误") return new Response(JSON.stringify({ error: "提供的密钥无效或无法生成令牌" }), { status: 400, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

          await db.prepare("INSERT INTO totp_keys (user_id, remark, secret) VALUES (?1, ?2, ?3)")
            .bind(user.id, remark.trim(), cleanedSecret) // Trim remark
            .run();
          return new Response(JSON.stringify({ success: true }), { status: 201, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        } catch (e) {
          console.error("API POST Key Error:", e);
          // Handle potential unique constraint violation if remark needs to be unique per user (adjust schema if needed)
          // if (e.message && e.message.includes('UNIQUE constraint failed')) { return new Response(JSON.stringify({ error: "备注已存在" }), { status: 409, ... }); }
          return new Response(JSON.stringify({ error: "添加密钥失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        }
      }
      // PUT /api/keys/:id
      const putMatch = path.match(/^\/api\/keys\/(\d+)$/);
      if (method === 'PUT' && putMatch) {
        try {
          const keyId = parseInt(putMatch[1]);
          const { remark } = await request.json();
          if (!remark || typeof remark !== 'string' || remark.trim().length === 0) return new Response(JSON.stringify({ error: "备注不能为空" }), { status: 400, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

          const { changes } = await db.prepare("UPDATE totp_keys SET remark = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(remark.trim(), keyId, user.id)
            .run();
          if (changes > 0) { return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } }); }
          else { return new Response(JSON.stringify({ error: "未找到密钥或无权修改" }), { status: 404, headers: { 'Content-Type': 'application/json; charset=utf-8' } }); }
        } catch (e) {
          console.error("API PUT Key Error:", e);
          return new Response(JSON.stringify({ error: "更新密钥失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        }
      }
      // DELETE /api/keys/:id
      const deleteMatch = path.match(/^\/api\/keys\/(\d+)$/);
      if (method === 'DELETE' && deleteMatch) {
        try {
          const keyId = parseInt(deleteMatch[1]);
          const { changes } = await db.prepare("DELETE FROM totp_keys WHERE id = ?1 AND user_id = ?2")
            .bind(keyId, user.id)
            .run();
          if (changes > 0) { return new Response(null, { status: 204 }); } // No Content success
          else { return new Response(JSON.stringify({ error: "未找到密钥或无权删除" }), { status: 404, headers: { 'Content-Type': 'application/json; charset=utf-8' } }); }
        } catch (e) {
          console.error("API DELETE Key Error:", e);
          return new Response(JSON.stringify({ error: "删除密钥失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
        }
      }

      // Fallback for unknown API routes
      return new Response(JSON.stringify({ error: "无效的 API 端点" }), { status: 404, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }


    // --- Page Routes ---

    // Login/Register Page (GET)
    if ((path === '/login' || path === '/register') && method === 'GET') {
      if (user) return Response.redirect(url.origin + '/', 302); // Redirect logged-in users to home
      const message = url.searchParams.get('message');
      const type = url.searchParams.get('type') || 'info';
      const defaultTab = path === '/register' ? 'register' : 'login';
      return new Response(loginRegisterPage(message, type, defaultTab), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Handle Login POST
    if (path === '/login' && method === 'POST') {
      if (user) return Response.redirect(url.origin + '/', 302);
      try {
        const formData = await request.formData();
        const username = formData.get('username');
        const password = formData.get('password');
        if (!username || !password) { return redirectWithMessage(url.origin + '/login', '用户名和密码不能为空', 'error', 302, '#login'); }

        const userRecord = await db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?1").bind(username).first();
        if (userRecord && await verifyPassword(userRecord.password_hash, password)) {
          const sessionValue = userRecord.username; // INSECURE - Use proper session token
          const headers = new Headers({
            'Location': '/',
            // Set secure cookie attributes
            'Set-Cookie': `${SESS_COOKIE_NAME}=${sessionValue}; path=/; HttpOnly; SameSite=Lax; Max-Age=86400${url.protocol === 'https:' ? '; Secure' : ''}` // 1 day expiry
          });
          return new Response(null, { status: 302, headers: headers });
        } else {
          return redirectWithMessage(url.origin + '/login', '用户名或密码错误', 'error', 302, '#login');
        }
      } catch (e) {
        console.error("Login POST Error:", e);
        return redirectWithMessage(url.origin + '/login', '登录时发生服务器错误', 'error', 302, '#login');
      }
    }

    // Handle Register POST
    if (path === '/register' && method === 'POST') {
      if (user) return Response.redirect(url.origin + '/', 302);
      try {
        const formData = await request.formData();
        const username = formData.get('username'); const password = formData.get('password'); const passwordConfirm = formData.get('password_confirm');

        // Basic server-side validation (complementary to client-side)
        if (!username || !password || !passwordConfirm) return redirectWithMessage(url.origin + '/register', '所有字段均为必填项', 'error', 302, '#register');
        if (username.length < 3) return redirectWithMessage(url.origin + '/register', '用户名长度至少需要3位', 'error', 302, '#register');
        if (password.length < 6) return redirectWithMessage(url.origin + '/register', '密码长度至少需要6位', 'error', 302, '#register');
        if (password !== passwordConfirm) return redirectWithMessage(url.origin + '/register', '两次输入的密码不一致', 'error', 302, '#register');

        try {
          const passwordHash = await hashPassword(password);
          await db.prepare("INSERT INTO users (username, password_hash) VALUES (?1, ?2)")
            .bind(username, passwordHash)
            .run();
          // Redirect to login page with success message
          return redirectWithMessage(url.origin + '/login', '注册成功，请登录', 'success', 302, '#login');
        } catch (dbError) {
          if (dbError.message && dbError.message.includes('UNIQUE constraint failed')) { // Check specific error
            return redirectWithMessage(url.origin + '/register', '用户名已被注册', 'error', 302, '#register');
          } else {
            console.error("Register DB Insert Error:", dbError);
            throw dbError; // Re-throw other DB errors
          }
        }
      } catch (e) {
        console.error("Register POST Error:", e);
        return redirectWithMessage(url.origin + '/register', '注册时发生服务器错误', 'error', 302, '#register');
      }
    }

    // Logout POST
    if (path === '/logout' && method === 'POST') {
      const headers = new Headers({
        'Location': '/login?message=' + encodeURIComponent('您已成功登出') + '&type=success',
        // Expire the cookie immediately
        'Set-Cookie': `${SESS_COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax${url.protocol === 'https:' ? '; Secure' : ''}`
      });
      return new Response(null, { status: 302, headers: headers });
    }

    // Add Key Page (GET)
    if (path === '/add' && method === 'GET') {
      const message = url.searchParams.get('message');
      const type = url.searchParams.get('type') || 'info';
      return new Response(addKeyPage(user, message, type), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Manage Keys Page (GET)
    if (path === '/manage' && method === 'GET') {
      let message = url.searchParams.get('message');
      let type = url.searchParams.get('type') || 'info';
      let keys = [];
      if (user) {
        try {
          const { results } = await db.prepare("SELECT id, remark, secret FROM totp_keys WHERE user_id = ?1 ORDER BY remark").bind(user.id).all();
          keys = results || [];
        } catch(e) {
          console.error("Manage Keys DB Error:", e);
          // Set message to display on the page itself
          message = '加载密钥列表时出错。';
          type = 'error';
          keys = []; // Ensure keys is empty on error
        }
      }
      // Pass potential error message to the page generator
      return new Response(manageKeysPage(keys, user, message, type), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Main Token Display Page (Root - GET)
    if (path === '/' && method === 'GET') {
      let keys = [];
      let dbErrorMessage = null;
      if (user) {
        try {
          const { results } = await db.prepare("SELECT id, remark, secret FROM totp_keys WHERE user_id = ?1 ORDER BY remark").bind(user.id).all();
          keys = results || [];
        } catch (e) {
          console.error("Token Display DB Error:", e);
          // Prepare an error message to potentially display
          dbErrorMessage = "加载令牌列表时发生数据库错误。";
          keys = []; // Ensure keys is empty on error
        }
      }
      // Render the page
      const htmlContent = displayTokensPage(keys, user);
      // If there was a DB error, inject it into the rendered HTML (basic approach)
      if (dbErrorMessage) {
        // Simple injection - might need a more robust method depending on page structure
        const errorHtml = `<article class="error-message message-display show" role="alert">\${escapeHtmlSrv(dbErrorMessage)}</article>`;
        // Inject before the token list or a prominent place
        const finalHtml = htmlContent.replace('<div id="token-list">', errorHtml + '<div id="token-list">');
        return new Response(finalHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      return new Response(htmlContent, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // --- Fallback 404 ---
    const notFoundBody = `<article><h2>404 - 页面未找到</h2><p>您请求的页面不存在。</p><a href="/" role="button" class="outline">返回首页</a></article>`;
    return new Response(generateHTML(notFoundBody, "404 未找到"), { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};
