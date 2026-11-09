const vscode = require("vscode");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const scrypt = promisify(crypto.scrypt);

const PASSWORD_KEY = "lockBlock.password.v1";

function activate(context) {
  let panel;
  let unlocked = false;
  let busy = false;

  const guard = require('./fileGuard')(context, {
    setUnlocked: value => {
      unlocked = value;
      render();
    },
    ensurePassword: async () => {
      if (busy) {
        return false;
      }
      busy = true;
      try {
        return Boolean(await context.secrets.get(PASSWORD_KEY)) || await setupPassword();
      } finally {
        busy = false;
      }
    },
    authenticate: async () => {
      if (busy) {
        return false;
      }
      busy = true;
      try {
        return await verifyPassword();
      } finally {
        busy = false;
      }
    }

  });

  function render() {
    if (!panel) {
      return;
    }

    panel.webview.html = getLockScreen(unlocked);
  }

  async function setupPassword() {
    const password = await vscode.window.showInputBox({
      title: "LockBlock — установка пароля",
      prompt: "Придумай пароль минимум из 8 символов",
      password: true,
      ignoreFocusOut: true,
      validateInput: (value) => {
        return value.length < 8
          ? "Нужно минимум 8 символов!!!!"
          : undefined;
      }
    });

    if (password === undefined) {
      return false;
    }

    const confirmation = await vscode.window.showInputBox({
      title: "LockBlock — подтверждение пароля",
      prompt: "Введи пароль ещё раз",
      password: true,
      ignoreFocusOut: true,
      validateInput: (value) => {
        return value !== password
          ? "Пароли не совпадают"
          : undefined;
      }
    });

    if (confirmation === undefined) {
      return false;
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const hash = await scrypt(password, salt, 64);

    await context.secrets.store(
      PASSWORD_KEY,
      JSON.stringify({
        salt,
        hash: hash.toString("hex")
      })
    );

    return true;
  }

  async function verifyPassword(suppliedPassword) {
    let saved = await context.secrets.get(PASSWORD_KEY);

    if (!saved) {
      const created = await setupPassword();

      if (!created) {
        return;
      }

      saved = await context.secrets.get(PASSWORD_KEY);
    }

    if (!saved) {
      return;
    }

    const password = suppliedPassword ?? await vscode.window.showInputBox({
      title: "LockBlock — вход",
      prompt: "Введи пароль для разблокировки",
      password: true,
      ignoreFocusOut: true
    });

    if (password === undefined) {
      return;
    }

    const record = JSON.parse(saved);

    const enteredHash = await scrypt(
      password,
      record.salt,
      64
    );

    const savedHash = Buffer.from(record.hash, "hex");

    const correct =
      enteredHash.length === savedHash.length &&
      crypto.timingSafeEqual(enteredHash, savedHash);

    if (!correct) {
      if (suppliedPassword === undefined) {
        vscode.window.showErrorMessage("Неверный пароль");
      }
      return;
    }

    return true;
  }

  const command = vscode.commands.registerCommand(
    "lockBlock.open",
    () => {
      if (panel) {
        panel.reveal(vscode.ViewColumn.One);
        return;
      }

      panel = vscode.window.createWebviewPanel(
        "lockBlock.screen",
        "LockBlock",
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          localResourceRoots: []
        }
      );

      render();

      panel.webview.onDidReceiveMessage(
        async (message) => {
          if (
            !message ||
            typeof message !== "object" ||
            !["unlock", "lock", "changePassword"].includes(message.type)
          ) {
            return;
          }

          if (busy) {
            return;
          }

          busy = true;

          try {
            if (message.type === "unlock") {
              if (typeof message.password !== "string" || message.password.length > 1024) {
                return;
              }
              const selected = guard.selection();
              if (await verifyPassword(message.password)) {
                await guard.unlock(selected);
              } else {
                panel?.webview.postMessage({ type: "error", text: "Неверный пароль" });
              }
            }

            if (message.type === "changePassword") {
              if (await verifyPassword()) {
                if (await setupPassword()) {
                  panel?.webview.postMessage({ type: "error", text: "Пароль изменён." });
                }
              }
            }

            if (message.type === "lock") {
              await guard.lock();
            }
          } catch {
            panel?.webview.postMessage({ type: "error", text: "Не удалось проверить пароль. Попробуй ещё раз." });
          } finally {
            busy = false;
            panel?.webview.postMessage({ type: "ready" });
          }
        },
        null,
        context.subscriptions
      );

      panel.onDidDispose(
        () => {
          panel = undefined;

        },
        null,
        context.subscriptions
      );
    }
  );

  context.subscriptions.push(command);
  void guard.check().catch(() => {
    vscode.window.showErrorMessage("Не удалось восстановить блокировку файлов.");
  });

  context.subscriptions.push({
    dispose: () => panel?.dispose()
  });
}

function getLockScreen(unlocked) {

  const nonce = crypto.randomBytes(16).toString("hex");

  const title = unlocked
    ? "Доступ открыт"
    : "Доступ закрыт";

  const description = unlocked
    ? "Пароль проверен. Можно снова закрыть доступ."
    : "Необходимо ввести пароль";

  const buttonText = unlocked
    ? "Заблокировать"
    : "Разблокировать";

  const action = unlocked ? "lock" : "unlock";

  return `
    <!DOCTYPE html>
    <html lang="ru">
      <head>
        <meta charset="UTF-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1.0"
        >

        <meta
          http-equiv="Content-Security-Policy"
          content="
            default-src 'none';
            style-src 'nonce-${nonce}';
            script-src 'nonce-${nonce}';
          "
        >

        <title>LockBlock</title>

        <style nonce="${nonce}">
          * {
            box-sizing: border-box;
          }

          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;

            font-family: var(--vscode-font-family);
            color: var(--vscode-editor-foreground);
            background: var(--vscode-editor-background);
          }

          .card {
            width: 100%;
            max-width: 440px;
            padding: 40px;
            text-align: center;

            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-widget-border, #7775);
            border-radius: 20px;
          }

          .brand {
            font-size: 11px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--vscode-descriptionForeground);
          }

          h1 {
            margin: 16px 0;
            font-size: 25px;
          }

          p {
            line-height: 1.65;
            color: var(--vscode-descriptionForeground);
          }

          button {
            width: 100%;
            margin-top: 20px;
            padding: 12px 18px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font: inherit;

            color: var(--vscode-button-foreground);
            background: var(--vscode-button-background);
          }

          button:hover {
            background: var(--vscode-button-hoverBackground);
          }

          button:focus-visible {
            outline: 2px solid var(--vscode-focusBorder);
            outline-offset: 4px;
          }

          label { display: block; text-align: left; margin: 20px 0 8px; }
          input[type="password"] {
            width: 100%; padding: 12px; border-radius: 8px; font: inherit;
            color: var(--vscode-input-foreground); background: var(--vscode-input-background);
            border: 1px solid var(--vscode-input-border, #7775);
          }
          input:focus-visible { outline: 2px solid var(--vscode-focusBorder); }
          #error { color: var(--vscode-errorForeground); min-height: 20px; }
          button:disabled { opacity: .6; cursor: wait; }
        </style>
      </head>

      <body>
        <main class="card">

          <div class="brand">LockBlock</div>

          <h1>${title}</h1>

          <p>${description}</p>

          <form id="login">
          ${unlocked ? "" : `<label for="password">Пароль</label>
          <input id="password" type="password" autocomplete="off" maxlength="1024" required>
          `}
          <p id="error" role="alert"></p>
          <button id="action" type="submit">
            ${buttonText}
          </button>
          </form>
          <button id="change-password" type="button">Сменить пароль</button>
        </main>

        <script nonce="${nonce}">
          const vscode = acquireVsCodeApi();

          const form = document.getElementById("login");
          const password = document.getElementById("password");
          const button = document.getElementById("action");
          const error = document.getElementById("error");
          form.addEventListener("submit", event => {
            event.preventDefault();
            if (button.disabled) {
              return;
            }
            error.textContent = "";
            button.disabled = true;
            vscode.postMessage({ type: "${action}", password: password?.value });
            if (password) {
              password.value = "";
            }
          });
          window.addEventListener("message", event => {
            if (event.data.type === "error") {
              error.textContent = event.data.text;
            }
            if (event.data.type === "ready") {
              button.disabled = false;
              password?.focus();
            }
          });
          document.getElementById("change-password").addEventListener("click", () => {
            if (button.disabled) {
              return;
            }
            button.disabled = true;
            vscode.postMessage({ type: "changePassword" });
          });
          password?.focus();
        </script>
      </body>
    </html>
  `;
}

module.exports = { activate };
