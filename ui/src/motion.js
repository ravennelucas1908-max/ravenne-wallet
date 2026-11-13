/* Motion engine — every function cites its mission rule (spec #n). */

const prefersReduced = () =>
  matchMedia("(prefers-reduced-motion: reduce)").matches || document.body.dataset.motion === "off";
const dur = n => prefersReduced() ? 0 : n;
const EASE_OUT = "cubic-bezier(0.16, 1, 0.3, 1)";      // spec #1
const EASE_INOUT = "cubic-bezier(0.65, 0, 0.35, 1)";   // spec #8

/* spec #13 — screens crossfade simultaneously (old leaves while new enters) */
export function switchScreen(fromEl, toEl) {
  if (fromEl && fromEl !== toEl) {
    fromEl.classList.add("leaving");        // spec #12 : sortie plus courte
    fromEl.classList.remove("on");
    setTimeout(() => fromEl.classList.remove("leaving"), dur(300));
  }
  toEl.classList.add("on");
}

/* spec #3 — list rows staggered 30 ms apart */
export function stagger(container) {
  [...container.children].forEach((el, i) => {
    el.style.setProperty("--i", i);
    el.classList.remove("done");
    el.classList.add("done");
    setTimeout(() => el.classList.add("done"), dur(380 + i * 30));
  });
}

/* spec #16 + #6 + #10 — shared-layout FLIP with a curved path (slight vertical
   arc), transform-origin computed from the trigger, never center-of-screen. */
const flips = new Map();
export function flipPersist(el, key, arc = 0.18) {
  if (prefersReduced()) return;
  const first = flips.get(key);
  const last = el.getBoundingClientRect();
  flips.set(key, last);
  if (!first) return;
  const dx = first.left - last.left;
  const dy = first.top - last.top;
  if (Math.abs(dx) < 2 && Math.abs(dy) < 2) return;
  el.classList.add("flip-moving");
  const midY = dy - Math.max(24, Math.abs(dy) * arc);   // spec #6 : arc, jamais ligne droite
  const anim = el.animate([
    { transform: `translate(${dx}px, ${dy}px) scaleX(${1 + Math.min(0.12, Math.abs(dx) / 400)})` }, // spec #5
    { transform: `translate(${dx / 2}px, ${midY / 2}) scale(1)` },
    { transform: "translate(0, 0) scale(1)" },
  ], { duration: dur(380), easing: EASE_INOUT });        // spec #8 : ease-in-out pour bouger
  anim.onfinish = () => el.classList.remove("flip-moving");
}

/* spec #10 — open a popover scaled from the trigger element */
export function openFromTrigger(popover, trigger) {
  const r = trigger.getBoundingClientRect();
  popover.style.transformOrigin = `${r.left > innerWidth / 2 ? "right" : "left"} top`;
  popover.classList.add("open");
}
export function closeToTrigger(popover) {
  popover.classList.remove("open");                      // spec #12 : sortie vers le déclencheur
}

/* spec #7 — success pulse (once) */
export function pulse(el) {
  if (prefersReduced()) return;
  el.classList.remove("pulse-success");
  void el.offsetWidth;                                   // restart animation
  el.classList.add("pulse-success");
  setTimeout(() => el.classList.remove("pulse-success"), 480);
}

/* spec #15 — icon crossfade with blur */
export function swapStateIcon(container, newHtml) {
  const old = container.querySelector(".old");
  if (old) { old.className = "new"; old.innerHTML = newHtml; }
  else { container.innerHTML = `<span class="old">${newHtml}</span>`; }
  container.classList.add("swap");
  setTimeout(() => container.classList.remove("swap"), dur(190));
}

/* spec #11 — rubber-band at scroll edges (the ONLY elastic exception) */
export function rubberBand(box) {
  box.addEventListener("scroll", () => {
    if (prefersReduced()) return;
    const max = box.scrollHeight - box.clientHeight;
    if (max <= 0) return;
    if (box.scrollTop < 0 || box.scrollTop > max) {
      box.classList.add("rubber");
      box.style.transform = `translateY(${box.scrollTop < 0 ? box.scrollTop : box.scrollTop - max}px)`;
    } else {
      box.classList.remove("rubber");
      box.style.transform = "";
    }
  }, { passive: true });
}

/* spec #14 — heavy reveal for modals/large cards */
export function reveal(el) {
  el.classList.add("reveal");
  setTimeout(() => el.classList.remove("reveal"), dur(450));
}
