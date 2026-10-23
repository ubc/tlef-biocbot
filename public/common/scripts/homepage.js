(function () {
    'use strict';

    var page = document.getElementById('bb-page');
    if (!page) return;

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // ── Local-login visibility (admin-controlled) ──────────────────────
    // Links start hidden in the markup; only reveal them once the admin
    // setting confirms local login is actually enabled. On any failure or
    // ambiguity, stay hidden rather than risk pointing people at a sign-in
    // path the admin turned off (mirrors login.js's own fail-safe default).
    fetch('/api/auth/methods')
        .then(function (r) { return r.json(); })
        .then(function (result) {
            var methods = result && result.methods;
            if (!methods) return;
            var allowLocalLogin = methods.local !== false && methods.allowLocalLogin !== false;
            if (!allowLocalLogin) return;
            page.querySelectorAll('.js-local-login-link').forEach(function (el) {
                el.hidden = false;
            });
        })
        .catch(function () { /* stay hidden */ });

    // ── Hero mode toggle + line cycling ────────────────────────────────
    var LINES = {
        tutor: [
            "Before we get to the rate law, what does PFK-1 do to fructose-6-phosphate?",
            "Good. So which step of glycolysis is the committed one, and why that one?",
            "Let's look at your notes from Monday. Where did the ATP count come from?"
        ],
        protege: [
            "Hi, I'm BiocBot. Teach me this unit?",
            "Wait, you said high ATP slows glycolysis. Isn't ATP what the cell wants?",
            "So is that second site the same place the sugar binds, or somewhere else?"
        ]
    };
    var MODE_NOTES = {
        tutor: "Tutor mode: BiocBot asks the questions and walks you through the unit.",
        protege: "Protégé mode: BiocBot plays the student and you do the explaining."
    };

    var botLineEl = document.getElementById('bb-bot-line');
    var modeNoteEl = document.getElementById('bb-mode-note');
    var modeBtns = Array.prototype.slice.call(page.querySelectorAll('[data-mode-btn]'));
    var mode = 'tutor';
    var lineIndex = 0;
    var cycleTimer = null;

    function renderLine() {
        if (botLineEl) botLineEl.textContent = LINES[mode][lineIndex];
        if (modeNoteEl) modeNoteEl.textContent = MODE_NOTES[mode];
    }

    function startCycle() {
        clearInterval(cycleTimer);
        cycleTimer = setInterval(function () {
            lineIndex = (lineIndex + 1) % 3;
            renderLine();
        }, 6000);
    }

    function setMode(next) {
        if (next === mode) return;
        mode = next;
        lineIndex = 0;
        modeBtns.forEach(function (btn) {
            btn.setAttribute('aria-pressed', String(btn.dataset.modeBtn === mode));
        });
        renderLine();
        startCycle();
    }

    modeBtns.forEach(function (btn) {
        btn.addEventListener('click', function () { setMode(btn.dataset.modeBtn); });
    });

    if (botLineEl) {
        renderLine();
        startCycle();
    }

    // Flip cards flip on hover/focus via CSS alone (see .bb-flip-card:hover
    // / :focus-within in homepage.css) — no click state to manage here.

    // ── Active nav highlighting ─────────────────────────────────────────
    var navLinks = Array.prototype.slice.call(page.querySelectorAll('[data-navlink]'));
    if (navLinks.length && 'IntersectionObserver' in window) {
        var navSections = navLinks
            .map(function (a) { return { a: a, sec: document.getElementById(a.dataset.navlink) }; })
            .filter(function (p) { return p.sec; });

        var navObserver = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                var pair = navSections.find(function (p) { return p.sec === entry.target; });
                if (!pair) return;
                pair.a.toggleAttribute('aria-current', entry.isIntersecting);
            });
        }, { rootMargin: '-140px 0px -60% 0px', threshold: 0 });

        navSections.forEach(function (p) { navObserver.observe(p.sec); });
    }

    // ── Scroll reveal ───────────────────────────────────────────────────
    if (!reducedMotion && 'IntersectionObserver' in window) {
        var revealObserver = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                entry.target.classList.add('bb-revealed');
                revealObserver.unobserve(entry.target);
            });
        }, { threshold: 0, rootMargin: '0px 0px -10% 0px' });

        page.querySelectorAll('.bb-reveal').forEach(function (el) { revealObserver.observe(el); });
    } else {
        page.querySelectorAll('.bb-reveal').forEach(function (el) { el.classList.add('bb-revealed'); });
    }

    // ── Stat counters (count up from 0 when scrolled into view) ─────────
    // The markup already has the real final value (e.g. "+5.5%") so the
    // page is correct even if this script never runs. STAT_PATTERN splits
    // that text into a non-digit prefix ("+", "~"), the number itself
    // (commas/decimals allowed), and a non-digit suffix ("%"), so the
    // animation can count up while preserving the original formatting.
    var STAT_PATTERN = /^([^\d]*)([\d,]+(?:\.\d+)?)([^\d]*)$/;
    var statEls = Array.prototype.slice.call(page.querySelectorAll('.bb-stat-num'));
    var stats = statEls.map(function (el) {
        var match = STAT_PATTERN.exec(el.textContent.trim());
        if (!match) return null;
        var rawNumber = match[2];
        var decimalPart = rawNumber.split('.')[1];
        return {
            el: el,
            prefix: match[1],
            suffix: match[3],
            decimals: decimalPart ? decimalPart.length : 0,
            target: parseFloat(rawNumber.replace(/,/g, ''))
        };
    }).filter(Boolean);

    function formatStat(stat, value) {
        var fixed = value.toFixed(stat.decimals);
        var parts = fixed.split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        return stat.prefix + parts.join('.') + stat.suffix;
    }

    function animateStat(stat) {
        var duration = 1200;
        var start = null;
        function step(timestamp) {
            if (start === null) start = timestamp;
            var progress = Math.min((timestamp - start) / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            stat.el.textContent = formatStat(stat, stat.target * eased);
            if (progress < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    if (stats.length && !reducedMotion && 'IntersectionObserver' in window) {
        var statObserver = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                var stat = stats.find(function (s) { return s.el === entry.target; });
                if (!stat || !entry.isIntersecting) return;
                stat.el.textContent = formatStat(stat, 0);
                animateStat(stat);
                statObserver.unobserve(entry.target);
            });
        }, { threshold: 0, rootMargin: '0px 0px -10% 0px' });

        stats.forEach(function (stat) { statObserver.observe(stat.el); });
    }

    // ── Gallery lightbox ────────────────────────────────────────────────
    var lightbox = document.getElementById('bb-lightbox');
    var lightboxImg = document.getElementById('bb-lightbox-img');
    var lightboxTitle = document.getElementById('bb-lightbox-title');
    var lightboxClose = document.getElementById('bb-lightbox-close');
    var lightboxPrev = document.getElementById('bb-lightbox-prev');
    var lightboxNext = document.getElementById('bb-lightbox-next');
    var galleryTriggers = Array.prototype.slice.call(page.querySelectorAll('.js-lightbox-trigger'));
    var lastTrigger = null;
    var currentIndex = 0;

    function titleFor(trigger) {
        var strong = trigger.parentElement && trigger.parentElement.querySelector('figcaption strong');
        return strong ? strong.textContent : '';
    }

    function showIndex(index) {
        var trigger = galleryTriggers[index];
        var img = trigger && trigger.querySelector('img');
        if (!img || !lightboxImg) return;
        currentIndex = index;
        lightboxImg.src = img.src;
        lightboxImg.alt = img.alt;
        if (lightboxTitle) lightboxTitle.textContent = titleFor(trigger);
    }

    function openLightbox(trigger) {
        var index = galleryTriggers.indexOf(trigger);
        if (index === -1 || !lightbox) return;
        lastTrigger = trigger;
        showIndex(index);
        lightbox.hidden = false;
        document.body.style.overflow = 'hidden';
        lightboxClose.focus();
    }

    function closeLightbox() {
        if (!lightbox || lightbox.hidden) return;
        lightbox.hidden = true;
        lightboxImg.src = '';
        document.body.style.overflow = '';
        if (lastTrigger) lastTrigger.focus();
    }

    function stepLightbox(delta) {
        if (!lightbox || lightbox.hidden || !galleryTriggers.length) return;
        var next = (currentIndex + delta + galleryTriggers.length) % galleryTriggers.length;
        showIndex(next);
    }

    galleryTriggers.forEach(function (trigger) {
        trigger.addEventListener('click', function () { openLightbox(trigger); });
    });

    if (lightboxClose) lightboxClose.addEventListener('click', closeLightbox);
    if (lightboxPrev) lightboxPrev.addEventListener('click', function () { stepLightbox(-1); });
    if (lightboxNext) lightboxNext.addEventListener('click', function () { stepLightbox(1); });
    if (lightbox) {
        lightbox.addEventListener('click', function (e) {
            if (e.target === lightbox) closeLightbox();
        });
    }
    document.addEventListener('keydown', function (e) {
        if (!lightbox || lightbox.hidden) return;
        if (e.key === 'Escape') closeLightbox();
        else if (e.key === 'ArrowLeft') stepLightbox(-1);
        else if (e.key === 'ArrowRight') stepLightbox(1);
    });
})();
