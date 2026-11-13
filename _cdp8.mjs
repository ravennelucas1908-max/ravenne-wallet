const list = await (await fetch("http://127.0.0.1:9223/json/list")).json();
const page = list.find(p => p.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id = 0;
const call = (method, params) => new Promise(res => {
  const i = ++id;
  ws.addEventListener("message", function h(ev) {
    const d = JSON.parse(ev.data);
    if (d.id === i) { ws.removeEventListener("message", h); res(d.result); }
  });
  ws.send(JSON.stringify({ id: i, method, params }));
});
const ev = async expr => (await call("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result?.value;
// Application → écran création de coffre
await ev("document.getElementById('mode-app').click()");
await new Promise(r => setTimeout(r, 600));
console.log("1. mode création:", await ev("document.getElementById('pass-go').textContent"),
  "| champ2:", await ev("!document.getElementById('pass-input2').classList.contains('hidden')"));
// crée le coffre
await ev("document.getElementById('pass-input').value = 'Ravenne1908'");
await ev("document.getElementById('pass-input2').value = 'Ravenne1908'");
await ev("document.getElementById('pass-go').click()");
await new Promise(r => setTimeout(r, 2500));
console.log("2. écran setup:", await ev("!!document.getElementById('su-go')"));
// génère les wallets
await ev("document.getElementById('su-n').value = 3");
await ev("document.getElementById('su-go').click()");
await new Promise(r => setTimeout(r, 3000));
console.log("3. seed:", await ev("(document.querySelector('#su-out .mono')?.textContent || '').split(' ').length + ' mots'"),
  "| ack:", await ev("!!document.getElementById('su-ack')"));
// coche + ouvre le wallet
await ev("document.getElementById('su-ack').checked = true; document.getElementById('su-ack').dispatchEvent(new Event('change'))");
await ev("document.getElementById('su-out').nextElementSibling?.click?.() || [...document.querySelectorAll('#su-out button')].pop().click()");
await new Promise(r => setTimeout(r, 8000));
console.log("4. écran wallet:", await ev("[...document.querySelectorAll('.screen.on')].map(s=>s.id)"),
  "| cartes:", await ev("[...document.querySelectorAll('#tab-overview .balance-val')].length"), "chaînes");
ws.close();
