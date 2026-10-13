"use strict";

/* The page. Every sentence comes from /strings by key. Every value that came from the server or the owner is put
   on the page with textContent, never as markup. */

const SESSION_HEADER = "X-AgentVax-Session";
const REFRESH_SECONDS = 15;
const SECONDS_PER_MINUTE = 60;
const MILLISECONDS = 1000;

const sessionToken = document.querySelector('meta[name="agentvax-session"]').getAttribute("content");
const mode = document.querySelector('meta[name="agentvax-mode"]').getAttribute("content");

let strings = {};
let wallet = null;
let walletRows = [];
const chatLogs = new Map();
let deadlines = [];
let refreshing = false;
let refreshAgain = false;

function t(key, values) {
  const template = strings[key];
  if (template === undefined) {
    return key;
  }
  return template.replace(/\{(\w+)\}/g, (match, name) => (values && name in values ? String(values[name]) : match));
}

function el(tag, options, children) {
  const node = document.createElement(tag);
  const settings = options || {};
  if (settings.text !== undefined) {
    node.textContent = settings.text;
  }
  if (settings.className) {
    node.className = settings.className;
  }
  if (settings.attributes) {
    for (const [name, value] of Object.entries(settings.attributes)) {
      node.setAttribute(name, value);
    }
  }
  for (const child of children || []) {
    node.appendChild(child);
  }
  return node;
}

function fill(parent, nodes) {
  parent.replaceChildren(...nodes);
}

function safeLink(address, label) {
  if (typeof address !== "string" || !/^https?:\/\//.test(address)) {
    return null;
  }
  return el("a", { text: label, attributes: { href: address, target: "_blank", rel: "noopener noreferrer" } });
}

function duration(seconds) {
  const units = [[86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]];
  for (const [size, unit] of units) {
    if (seconds >= size) {
      const count = Math.floor(seconds / size);
      return t("duration." + unit + (count === 1 ? ".one" : ".other"), { count });
    }
  }
  return t("duration.second.other", { count: 0 });
}

function say(text, isError) {
  const status = document.getElementById("status");
  status.textContent = text;
  status.className = isError ? "error" : "";
}

function forWallet(path) {
  return path + "?wallet=" + encodeURIComponent(wallet);
}

async function send(path, body) {
  const response = await fetch("/api" + forWallet(path), {
    method: "POST",
    headers: { "Content-Type": "application/json", [SESSION_HEADER]: sessionToken },
    body: JSON.stringify(body || {}),
  });
  let data = null;
  try {
    data = await response.json();
  } catch (error) {
    data = null;
  }
  return { status: response.status, data };
}

function resultText(outcome) {
  if (outcome.data && typeof outcome.data.text === "string") {
    return outcome.data.text;
  }
  if (outcome.data && typeof outcome.data.detail === "string") {
    return outcome.data.detail;
  }
  return t("ui.error.unknown");
}

async function act(path, body) {
  const outcome = await send(path, body);
  const ok = Boolean(outcome.data && outcome.data.ok);
  say(resultText(outcome), !ok);
  await refresh();
  return outcome;
}

/* ------------------------------------------------------------------------------------ strings in the page */

function applyStrings() {
  for (const node of document.querySelectorAll("[data-string]")) {
    node.textContent = t(node.getAttribute("data-string"));
  }
  const badge = document.getElementById("mode-badge");
  if (mode === "mock") {
    badge.textContent = t("ui.badge.mock");
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }
}

/* ------------------------------------------------------------------------------------ countdowns */

function countdown(secondsLeft) {
  const entry = { node: el("span", { className: "countdown" }), due: performance.now() / MILLISECONDS + secondsLeft };
  deadlines.push(entry);
  paint(entry);
  return entry.node;
}

function paint(entry) {
  const left = Math.max(0, Math.ceil(entry.due - performance.now() / MILLISECONDS));
  entry.node.textContent = left === 0 ? t("ui.countdown.ready") : t("ui.countdown.left", { time: duration(left) });
}

setInterval(() => deadlines.forEach(paint), MILLISECONDS);

/* ------------------------------------------------------------------------------------ rendering */

function renderMandate(mandate) {
  document.getElementById("mission").textContent = mandate.mission === null
    ? t("ui.mandate.mission_unknown")
    : t("ui.mandate.mission", { mission: mandate.mission });
  fill(document.getElementById("mandate-lines"), mandate.lines.map((line) => el("li", { text: line })));
  fill(
    document.querySelector("#mandate-fields tbody"),
    mandate.fields.map((field) => el("tr", {}, [el("th", { text: field.label }), el("td", { text: field.value })])),
  );
}

function renderFinancial(financial, allowance) {
  fill(document.getElementById("financial-lines"), financial.lines.map((line) => el("li", { text: line })));
  const meter = document.getElementById("allowance-meter");
  meter.value = allowance.fraction;
  document.getElementById("allowance-text").textContent = allowance.text;
}

function itemButton(label, handler, className) {
  const button = el("button", { text: label, className: className || "", attributes: { type: "button" } });
  button.addEventListener("click", handler);
  return button;
}

function renderPending(pending) {
  document.getElementById("pending-empty").hidden = pending.length > 0;
  fill(document.getElementById("pending-list"), pending.map((item) => {
    const lines = [el("p", { text: item.text })];
    const header = el("p", { className: "facts" }, [el("span", { text: t("ui.pending.tier", { tier: item.tier }) + " " })]);
    if (item.seconds_left !== null) {
      header.appendChild(countdown(item.seconds_left));
    } else {
      header.appendChild(el("span", { text: t("ui.pending.awaiting") }));
    }
    lines.push(header);
    if (item.flag_labels.length > 0) {
      lines.push(el("p", { className: "flags", text: t("ui.pending.flags", { flags: item.flag_labels.join(", ") }) }));
    }
    if (item.matching_capsules.length > 0) {
      lines.push(el("p", { className: "flags", text: t("ui.pending.alerts", { ids: item.matching_capsules.join(", ") }) }));
    }
    const buttons = el("div", { className: "buttons" });
    buttons.appendChild(itemButton(t("ui.pending.cancel"), () => act("/owner/cancel", { item_id: item.item_id })));
    if (item.can_approve) {
      buttons.appendChild(itemButton(t("ui.pending.approve"), () => openApproval(item)));
    }
    if (item.can_execute) {
      buttons.appendChild(itemButton(t("ui.pending.execute"), () => act("/owner/execute", { item_id: item.item_id })));
    }
    buttons.appendChild(itemButton(t("ui.pending.extend"), () => openExtend(item)));
    buttons.appendChild(itemButton(t("ui.pending.attack"), () => openAttack(item)));
    lines.push(buttons);
    return el("li", { className: "item tier" + item.tier }, lines);
  }));
}

function renderChanges(changes) {
  fill(document.getElementById("change-list"), changes.map((change) => {
    const title = change.name === null ? change.kind_label : change.kind_label + ": " + change.name;
    const row = el("li", {}, [el("p", { text: title }), el("p", { text: change.text }), countdown(change.seconds_left)]);
    const buttons = el("div", { className: "buttons" });
    if (change.can_apply && change.kind === "add_payee") {
      buttons.appendChild(itemButton(t("ui.changes.apply"), () => act("/owner/payees/apply", { change_id: change.change_id })));
    }
    buttons.appendChild(itemButton(t("ui.changes.cancel"), () => act("/owner/changes/cancel", { change_id: change.change_id })));
    row.appendChild(buttons);
    return row;
  }));
}

function renderPayees(payees) {
  fill(document.getElementById("payee-list"), payees.map((payee) => el("li", {}, [
    el("strong", { text: payee.name }),
    el("span", { text: " " + payee.text + " " }),
    el("code", { text: payee.account }),
  ])));
}

function renderLog(log) {
  document.getElementById("log-empty").hidden = log.length > 0;
  fill(document.getElementById("log-list"), log.map((entry) => {
    const meta = t("ui.log.meta", {
      tier: entry.tier,
      check: t("check." + entry.deciding_check),
      time: new Date(entry.at * MILLISECONDS).toLocaleString(),
    });
    const children = [el("p", { className: "facts", text: meta }), el("p", { text: entry.text })];
    const link = safeLink(entry.link, t("ui.log.explorer"));
    if (link !== null) {
      children.push(el("p", {}, [link]));
    }
    return el("li", { className: "tier" + entry.tier }, children);
  }));
}

function render(state) {
  deadlines = [];
  document.getElementById("frozen-badge").hidden = !state.frozen;
  renderMandate(state.mandate);
  renderFinancial(state.financial, state.allowance);
  renderPending(state.pending);
  renderChanges(state.changes);
  renderPayees(state.payees);
  renderLog(state.log);
}

async function refresh() {
  if (refreshing) {
    refreshAgain = true;
    return;
  }
  refreshing = true;
  try {
    do {
      refreshAgain = false;
      const asked = wallet;
      const response = await fetch(forWallet("/api/state"));
      if (!response.ok) {
        say(t("ui.error.state"), true);
        return;
      }
      const state = await response.json();
      if (asked === wallet) {
        render(state);
      }
    } while (refreshAgain);
  } finally {
    refreshing = false;
  }
}

/* ------------------------------------------------------------------------------------ dialogs */

const dialog = document.getElementById("dialog");
let onConfirm = null;

function openDialog(title, bodyNodes, confirmLabel, handler) {
  document.getElementById("dialog-title").textContent = title;
  fill(document.getElementById("dialog-body"), bodyNodes);
  document.getElementById("dialog-message").textContent = "";
  document.getElementById("dialog-confirm").textContent = confirmLabel;
  onConfirm = handler;
  dialog.showModal();
}

document.getElementById("dialog-close").addEventListener("click", () => dialog.close());
document.getElementById("dialog-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (onConfirm === null) {
    return;
  }
  const outcome = await onConfirm();
  const ok = Boolean(outcome && outcome.data && outcome.data.ok);
  document.getElementById("dialog-message").textContent = outcome ? resultText(outcome) : "";
  if (ok) {
    say(resultText(outcome), false);
    dialog.close();
    await refresh();
  }
});

function labelled(id, label, control) {
  return el("div", { className: "field" }, [el("label", { text: label, attributes: { for: id } }), control]);
}

function openApproval(item) {
  const body = [el("p", { text: item.text })];
  const confirmation = item.confirmation;
  let typed = null;
  const radios = [];
  if (confirmation !== null) {
    for (const line of confirmation.lines) {
      body.push(el("p", { text: line }));
    }
    typed = el("input", { attributes: { id: "typed-name", autocomplete: "off", spellcheck: "false" } });
    body.push(labelled("typed-name", t("ui.approval.type_name"), typed));
    const group = el("fieldset", {}, [el("legend", { text: t("confirm.who_asked") })]);
    for (const option of confirmation.requesters) {
      const radio = el("input", { attributes: { type: "radio", name: "requester", value: option.value, id: "who-" + option.value } });
      radios.push(radio);
      group.appendChild(el("div", {}, [radio, el("label", { text: option.label, attributes: { for: "who-" + option.value } })]));
    }
    body.push(group);
  }
  openDialog(t("ui.approval.heading"), body, t("ui.approval.confirm"), () => {
    const payload = { item_id: item.item_id };
    if (confirmation !== null) {
      const chosen = radios.find((radio) => radio.checked);
      if (chosen === undefined) {
        return Promise.resolve({ status: 422, data: { ok: false, text: t("ui.approval.choose") } });
      }
      payload.confirmation = { typed_payee_name: typed.value, requester: chosen.value };
    }
    return send("/owner/approve", payload);
  });
}

function openExtend(item) {
  const minutes = el("input", { attributes: { id: "extra-minutes", type: "number", min: "1", max: "43200", value: "10" } });
  openDialog(t("ui.extend.heading"), [
    el("p", { text: t("ui.extend.note") }),
    labelled("extra-minutes", t("ui.extend.minutes"), minutes),
  ], t("ui.extend.confirm"), () => {
    const value = Number.parseInt(minutes.value, 10);
    if (!Number.isInteger(value) || value < 1) {
      return Promise.resolve({ status: 422, data: { ok: false, text: t("ui.extend.invalid") } });
    }
    return send("/owner/extend-hold", { item_id: item.item_id, extra_seconds: value * SECONDS_PER_MINUTE });
  });
}

function openAttack(item) {
  const channel = el("select", { attributes: { id: "attack-channel" } });
  for (const name of ["message", "web_page", "token_metadata", "owner_chat"]) {
    channel.appendChild(el("option", { text: t("ui.channel." + name), attributes: { value: name } }));
  }
  const publish = el("input", { attributes: { id: "attack-publish", type: "checkbox", checked: "checked" } });
  openDialog(t("ui.attack.heading"), [
    el("p", { text: t("ui.attack.note") }),
    labelled("attack-channel", t("ui.attack.channel"), channel),
    el("div", {}, [publish, el("label", { text: t("ui.attack.publish"), attributes: { for: "attack-publish" } })]),
  ], t("ui.attack.confirm"), () => send("/owner/confirm-attack", {
    item_id: item.item_id,
    channel: channel.value,
    publish: publish.checked,
  }));
}

/* ------------------------------------------------------------------------------------ forms */

function chatOf(label) {
  if (!chatLogs.has(label)) {
    chatLogs.set(label, el("div"));
  }
  return chatLogs.get(label);
}

function addChat(className, text, extra) {
  const log = document.getElementById("chat-log");
  const row = el("div", { className: "message " + className }, [el("p", { text })]);
  for (const node of extra || []) {
    row.appendChild(node);
  }
  chatOf(wallet).appendChild(row);
  log.scrollTop = log.scrollHeight;
}

document.getElementById("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const instruction = document.getElementById("instruction");
  const documentText = document.getElementById("document-text");
  const body = { instruction: instruction.value, documents: [] };
  if (documentText.value.trim() !== "") {
    body.documents.push({ channel: document.getElementById("document-channel").value, text: documentText.value });
  }
  addChat("owner", instruction.value);
  const outcome = await send("/chat", body);
  if (outcome.status === 200 && outcome.data && outcome.data.reply) {
    const reply = outcome.data.reply;
    const extra = [];
    if (reply.tier !== null && reply.tier !== undefined) {
      extra.push(el("p", { className: "facts", text: t("ui.chat.tier", { tier: reply.tier }) }));
    }
    const link = safeLink(outcome.data.link, t("ui.log.explorer"));
    if (link !== null) {
      extra.push(el("p", {}, [link]));
    }
    addChat("agent " + reply.kind, reply.text, extra);
    instruction.value = "";
    documentText.value = "";
  } else {
    addChat("agent error", resultText(outcome));
  }
  await refresh();
});

document.getElementById("freeze").addEventListener("click", () => act("/owner/freeze"));

document.getElementById("payee-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = document.getElementById("payee-name");
  const account = document.getElementById("payee-account");
  const outcome = await act("/owner/payees/propose", { name: name.value, account: account.value });
  if (outcome.data && outcome.data.ok) {
    name.value = "";
    account.value = "";
  }
});

document.getElementById("income-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const amount = document.getElementById("income-amount");
  const date = document.getElementById("income-date");
  const when = Math.floor(new Date(date.value).getTime() / MILLISECONDS);
  if (!Number.isInteger(when) || when < 1) {
    say(t("ui.income.invalid"), true);
    return;
  }
  const outcome = await act("/owner/expected-income", { amount: amount.value, expected_at: when });
  if (outcome.data && outcome.data.ok) {
    amount.value = "";
    date.value = "";
  }
});

/* ------------------------------------------------------------------------------------ wallets */

function chooseWallet(label) {
  wallet = label;
  window.location.hash = label;
  const row = walletRows.find((candidate) => candidate.label === label);
  document.getElementById("wallet-about").textContent = row && row.about !== null ? row.about : "";
  fill(document.getElementById("chat-log"), [chatOf(label)]);
  document.getElementById("dialog").close();
  say("", false);
  return refresh();
}

async function loadWallets() {
  const response = await fetch("/api/wallets");
  walletRows = await response.json();
  const select = document.getElementById("wallet-select");
  fill(select, walletRows.map((row) => el("option", { text: t("ui.wallet.option", { label: row.label }), attributes: { value: row.label } })));
  select.addEventListener("change", () => chooseWallet(select.value));
  const wanted = window.location.hash.replace("#", "");
  const initial = walletRows.some((row) => row.label === wanted) ? wanted : walletRows[0].label;
  select.value = initial;
  await chooseWallet(initial);
}

/* ------------------------------------------------------------------------------------ start */

async function start() {
  const response = await fetch("/strings");
  strings = await response.json();
  applyStrings();
  await loadWallets();
  setInterval(refresh, REFRESH_SECONDS * MILLISECONDS);
}

start();
