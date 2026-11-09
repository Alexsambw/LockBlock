const vscode = require("vscode");
const path = require("node:path");

function contains(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (relative !== ".." &&
    !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative));
}

module.exports = function createFileGuard(context, access) {
  let rules = context.workspaceState.get("protectedPaths", []);
  const grants = new Set();
  let target;
  let checking = false;

  function ruleFor(uri) {
    if (uri.scheme !== "file") {
      return;
    }
    return rules.filter(rule => rule.path === uri.fsPath ||
      (rule.directory && contains(rule.path, uri.fsPath)))
      .sort((a, b) => b.path.length - a.path.length)[0];
  }

  function blocked(uri) {
    const rule = ruleFor(uri);
    return rule && rule.protected !== false && !grants.has(rule.path);
  }

  function tabUris(tab) {
    const input = tab.input;
    const is = name => typeof vscode[name] === "function" && input instanceof vscode[name];
    if (is("TabInputText") || is("TabInputCustom") || is("TabInputNotebook")) {
      return [input.uri];
    }
    if (is("TabInputTextDiff") || is("TabInputNotebookDiff")) {
      return [input.original, input.modified];
    }
    if (is("TabInputTextMerge")) {
      return [input.base, input.input1, input.input2, input.result];
    }
    return [];
  }

  async function reopen(selected) {
    const input = selected.input;
    if (input && (input instanceof vscode.TabInputTextDiff ||
        (vscode.TabInputNotebookDiff && input instanceof vscode.TabInputNotebookDiff))) {
      return vscode.commands.executeCommand("vscode.diff", input.original, input.modified);
    }
    if (vscode.TabInputCustom && input instanceof vscode.TabInputCustom) {
      return vscode.commands.executeCommand("vscode.openWith", selected.uri, input.viewType);
    }
    if (vscode.TabInputNotebook && input instanceof vscode.TabInputNotebook) {
      return vscode.commands.executeCommand("vscode.openWith", selected.uri, input.notebookType);
    }
    return vscode.commands.executeCommand("vscode.open", selected.uri);
  }

  async function check() {
    if (checking) {
      return;
    }
    checking = true;
    try {
      let found = false;
      for (const group of vscode.window.tabGroups.all) {
        for (const tab of [...group.tabs]) {
          const uri = tabUris(tab).find(blocked);
          if (!uri || tab.isDirty) {
            continue;
          }
          target = { uri, rule: ruleFor(uri).path, input: tab.input };
          await vscode.window.tabGroups.close(tab, true);
          found = true;
        }
      }
      if (found) {
        access.setUnlocked(false);
        await vscode.commands.executeCommand("lockBlock.open");
      }
    } finally {
      checking = false;
    }
  }

  async function save(next) {
    await context.workspaceState.update("protectedPaths", next);
    rules = next;
  }

  function command(id, handler) {
    context.subscriptions.push(vscode.commands.registerCommand(id, async uri => {
      uri = uri || vscode.window.activeTextEditor?.document.uri;
      if (!uri || uri.scheme !== "file") {
        return;
      }
      try {
        const allowed = id === "lockBlock.protect"
          ? await access.ensurePassword()
          : await access.authenticate();
        if (allowed) {
          await handler(uri);
        }
      } catch {
        vscode.window.showErrorMessage("Не удалось изменить защиту файла.");
      }
    }));
  }

  command("lockBlock.protect", async uri => {
    const stat = await vscode.workspace.fs.stat(uri);
    const directory = Boolean(stat.type & vscode.FileType.Directory);
    if (vscode.window.tabGroups.all.some(group => group.tabs.some(tab =>
      tab.isDirty && tabUris(tab).some(item => directory
        ? contains(uri.fsPath, item.fsPath) : item.fsPath === uri.fsPath)))) {
      vscode.window.showWarningMessage("Сначала сохрани изменения в выбранных файлах.");
      return;
    }

    await save([...rules.filter(rule => !contains(uri.fsPath, rule.path)),
      { path: uri.fsPath, directory, protected: true }]);
    for (const granted of grants) {
      if (contains(uri.fsPath, granted)) {
        grants.delete(granted);
      }
    }
    target = { uri, rule: uri.fsPath };
    access.setUnlocked(false);
    await check();
    await vscode.commands.executeCommand("lockBlock.open");
  });

  command("lockBlock.unprotect", async uri => {
    const stat = await vscode.workspace.fs.stat(uri);

    await save([...rules.filter(rule => !contains(uri.fsPath, rule.path)), {
      path: uri.fsPath,
      directory: Boolean(stat.type & vscode.FileType.Directory),
      protected: false
    }]);
    for (const granted of grants) {
      if (contains(uri.fsPath, granted)) {
        grants.delete(granted);
      }
    }
    if (target && contains(uri.fsPath, target.uri.fsPath)) {
      target = undefined;
      access.setUnlocked(false);
    }
  });

  context.subscriptions.push(vscode.workspace.onWillRenameFiles(event => {
    event.waitUntil((async () => {
      const moves = event.files.map(({ oldUri, newUri }) => ({
        oldPath: oldUri.fsPath,
        newPath: newUri.fsPath,
        inherited: ruleFor(oldUri),
        oldUri
      }));
      function relocated(value) {
        const move = moves.find(item => contains(item.oldPath, value));
        return move ? path.join(move.newPath, path.relative(move.oldPath, value)) : value;
      }
      const next = rules.map(rule => ({ ...rule, path: relocated(rule.path) }));
      for (const move of moves) {

        if (!move.inherited || next.some(rule => rule.path === move.newPath)) {
          continue;
        }
        const stat = await vscode.workspace.fs.stat(move.oldUri);
        next.push({
          path: move.newPath,
          directory: Boolean(stat.type & vscode.FileType.Directory),
          protected: move.inherited.protected !== false
        });
      }
      await save(next);
      const granted = [...grants].map(relocated);
      grants.clear();
      for (const value of granted) {
        grants.add(value);
      }

      target = undefined;
      access.setUnlocked(false);
    })());
  }));

  context.subscriptions.push(vscode.window.tabGroups.onDidChangeTabs(() => {
    void check().catch(() => vscode.window.showErrorMessage("Не удалось закрыть защищённую вкладку."));
  }));

  return {
    check,
    selection: () => target,
    async unlock(selected = target) {
      if (!selected || selected !== target) {
        return;
      }
      grants.add(selected.rule);
      access.setUnlocked(true);
      await reopen(selected);
    },
    async lock() {
      if (!target) {
        return;
      }
      const selected = target;
      const dirty = vscode.window.tabGroups.all.some(group => group.tabs.some(tab =>
        tab.isDirty && tabUris(tab).some(uri => ruleFor(uri)?.path === selected.rule)));
      if (dirty) {
        vscode.window.showWarningMessage("Сначала сохрани изменения в защищённых файлах.");
        return;
      }
      grants.delete(selected.rule);
      access.setUnlocked(false);
      await check();
    }
  };
};
