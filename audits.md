# BiocBot Accessibility Audit

**Date:** 2026-07-20 (pre-meeting audit — no code changes made)
**Scope:** All 20 HTML pages under `public/` (login, 6 student pages, 10 instructor pages, 3 TA pages), the shared scripts that generate dialogs and dynamic UI, and the shared stylesheets.
**Method:** Static review of markup + the JS that builds/controls modals, focus, and keyboard behavior. Checked against WCAG 2.2 A/AA, the W3C page-structure tutorial, and the dialog/heading/skip-link requirements previously outlined by the accessibility specialist. Cross-referenced with [The A11Y Project's note on automated tools](https://www.a11yproject.com/posts/automated-tools-can-ensure-full-accessibility-compliance/) — automated scanners (like our axe suite) catch roughly a third of issues; everything in this document was found by manual review, and most of it would **not** be caught by axe.

> Legend: 🔴 blocker (breaks a flow for AT/keyboard users) · 🟠 serious · 🟡 moderate · ✅ positive (already done right — worth showing tomorrow)

---

## 1. Systemic issues (affect every page)

These repeat across the whole app because pages share the same sidebar/modal templates. Fixing the template fixes ~20 pages at once.

### 1.1 🔴 No skip link anywhere (WCAG 2.4.1 Bypass Blocks)
No page has a "Skip to main content" link. A keyboard user must tab through the entire sidebar (logo, 5–9 nav links, New Session button, Settings, Logout) on **every page load** before reaching the content. The specialist's prescription is not implemented anywhere:
- No `<h1 id="main" tabindex="-1">` target exists on any page.
- No `.skip-link` CSS exists in any stylesheet (`grep` for "skip" across `public/` returns nothing).

**Fix (per specialist):** `<p class="skip-link"><a href="#main">Skip to main content</a></p>` as the first focusable element on every page; `id="main"` + `tabindex="-1"` on each page's `<h1>`; visually hidden until `:focus-visible`.

### 1.2 🟠 Sidebar is `<aside>` ("complementary") instead of `<header>` ("banner")
Every app page uses `<aside class="sidebar">` for the primary site navigation + user identity block. The specialist explicitly recommended making this a `<header>` (banner landmark). Files: every page under `public/student/`, `public/instructor/`, `public/ta/` (e.g. [student/index.html:22](public/student/index.html), [instructor/home.html:22](public/instructor/home.html), [ta/home.html:22](public/ta/home.html)).

Additionally, the **login page ([index.html](public/index.html)) has no landmarks at all** — no `<main>`, no `<header>`, no `<nav>`. Everything is in generic `<div>`s.

### 1.3 🟠 Current-page nav links have no `aria-current="page"`
The "you are here" state is conveyed only by the visual `.active` class on the `<li>`. No `aria-current="page"` anywhere in the static nav markup. Screen-reader users get no equivalent of the highlight.
- Only exception: [settings.js:96](public/instructor/scripts/settings.js) sets `aria-current="true"` on settings **rail** links (should arguably be `"page"`/`"true"` is acceptable, but note the sidebar nav on that same page still has nothing). ✅ pattern exists — just needs to be applied to the main sidebar on all pages.
- Also note the class is on the `<li>`, not the `<a>`; `aria-current` belongs on the `<a>`.

### 1.4 🔴 Mobile header toggle missing name + state (WCAG 4.1.2 Name/Role/Value)
[mobile-layout.js](public/common/scripts/mobile-layout.js) creates `button.mobile-header-toggle` with:
- **No `aria-expanded`** — the exact issue the specialist already flagged. State changes are conveyed only by swapping ▲/▼ glyphs.
- **No accessible name** — content is `<span class="toggle-icon">▲</span>` and only a `title="Toggle Header"` attribute (title is unreliable as a name and never visible to touch users). The announced name will be "▲, button" or similar.
- **No `aria-controls`** pointing at the collapsed region.

**Fix:** `aria-expanded="false"` → toggle to `"true"` on click; `aria-label="Toggle navigation"` (or visually hidden text); or replace with `<details>/<summary>` per the specialist's option 1.

### 1.5 🔴 Every modal is a generic `<div>` — zero `<dialog>` elements in the codebase
`grep` for `<dialog` across all HTML/JS: **0 results.** Every modal in the app is `div.modal` / `div.modal-overlay` / `div.agreement-modal-overlay` toggled with `display` or a `.show` class. Consequences (per modal detail in §3):
- No `role="dialog"` (except 3 late additions, see §3 table), so no accessible name can even be assigned on most.
- **No focus trap on any modal in the app.** Tab walks straight out into the obscured page behind — the exact issue the specialist demonstrated on first load.
- **Focus is not moved into the modal on open** for most modals (exceptions in §3).
- **Focus is not returned to the trigger on close** anywhere (the `<dialog>` element would do this for free).
- **Escape does not close** most modals (exceptions: agreement modal in read-only mode, chat survey, settings transfer modal).
- Backdrop `div`s don't have `aria-hidden` management, so background content stays in the accessibility tree while the modal is "open."

### 1.6 🟠 Modal close buttons are named "×"
Every `button.modal-close` has literal text `×` and no `aria-label` (e.g. [instructor/index.html:105](public/instructor/index.html), [ta-hub.html:82](public/instructor/ta-hub.html), [topic-review.js:277](public/common/scripts/topic-review.js)). Announced as "multiplication sign, button" or just "times." Needs `aria-label="Close"`.

### 1.7 🟠 Unnamed toggle switches (checkbox with empty label)
The visual toggle pattern `<input type="checkbox"><label class="toggle-slider"></label>` / `<span class="toggle-slider">` leaves the checkbox with **no accessible name** in several places:
- **Student chat mode toggle** [student/index.html:92-93](public/student/index.html) — `#mode-toggle-checkbox` with an *empty* `<label class="toggle-slider">`. This is the Tutor/Protégé switch, a core control, and it announces as "checkbox, checked" with no name. The "Protégé"/"Tutor" text spans next to it are not associated with it, and the active mode is conveyed by a color class only.
- **Unit publish toggles** [instructor-units.js:200-204](public/instructor/scripts/instructor-units.js) — `#publish-${unitId}` checkbox, no name, no label text. This is the control that publishes/unpublishes a unit to students.
- ✅ Contrast: the toggles in [settings.html](public/instructor/settings.html) all carry `aria-labelledby`/`aria-describedby` — that page is the model to copy.

### 1.8 🟠 Hover-only tooltips (WCAG 1.4.13 / keyboard access)
`.info-icon.tooltip` spans with `data-tooltip` ([home.css:1179-1224](public/styles/home.css), used throughout [instructor/home.html](public/instructor/home.html)) reveal content **only** via `:hover::after` CSS. Not focusable, no `:focus` trigger, content invisible to keyboard and screen-reader users, and not dismissible/hoverable per 1.4.13. The tooltip text often carries real explanations ("Total unique students who have struggled…"). Recommend converting to a focusable disclosure (button + describedby, or `<details>`).

### 1.9 🟡 No global `:focus-visible` strategy
Focus styling exists piecemeal (inputs/textareas get border-color changes; [settings.css](public/styles/settings.css) properly uses `:focus-visible` on tiles/rail links ✅). But many interactive elements — sidebar nav links, modal buttons, `.action-btn`, accordion headers, download dropdown items — rely on the browser default outline, and several stylesheets set custom borders/`outline: none`-adjacent patterns on focus (e.g. `.agreement-modal:focus`). Needs a review pass with the specialist's 3:1 contrast requirement for focus indicators (Sara Soueidan reference from his notes).

### 1.10 🟡 Decorative emoji inside headings and buttons
Headings like `<h2>🎓 Complete Your Onboarding</h2>`, `<h2>📊 Course Statistics</h2>`, `<h2>⚠️ Struggle Topics</h2>` ([instructor/home.html](public/instructor/home.html)) get emoji announced as part of the heading ("graduation cap Complete Your Onboarding"). Same for 📁/📝 in upload buttons, 🎉 headings in onboarding. Wrap in `<span aria-hidden="true">`.

### 1.11 🟡 Loading/dynamic status changes are mostly silent
Loading spinners, "Loading topics…", empty states, and error states are swapped via `display` with no `role="status"`/`aria-live` in most places, so screen-reader users don't hear when content finishes loading or fails. ✅ Exceptions done right: [notifications.js](public/common/scripts/notifications.js) (toast container has `role="status"` + `aria-live="polite"` + labeled dismiss button — great), academic sync status in onboarding, `field-feedback` errors with `role="alert"`, TA course summary, super-course panels.

---

## 2. Heading hierarchy per page (skipped levels + missing `<h1>`s)

Rule set used (from the specialist): `<main>` content starts at `<h1>`; headings before/after main (sidebar) may start at `<h2>`; no skipped levels among visible headings; dialogs start at `<h2>`.

The shared sidebar's `<h2>BiocBot</h2>` before `<main>` is **acceptable** per that rule and is not re-flagged below.

| Page | Outline (visible, in `<main>` unless noted) | Issues |
|---|---|---|
| [index.html](public/index.html) (login) | h1 BiocBot → h2 Sign In → h2 Create Account (hidden until toggled) | ✅ order OK; 🟠 no `<main>` landmark at all |
| [student/index.html](public/student/index.html) (chat) | h1 Chat with BiocBot | ✅ OK (verify JS-injected message content adds no headings) |
| [student/dashboard.html](public/student/dashboard.html) | h1 → **h3 Active Topics, h3 Directive Mode Active** → h2 Course Topics → h2 Your Active Topics | 🟠 h1→h3 skip (summary cards should be h2, or the cards' titles arguably shouldn't be headings at all) |
| [student/quiz.html](public/student/quiz.html) | h1 → **h4 Review Materials** → h2 All Done! | 🟠 h1→h4 skip; 🟡 "Need help understanding this?" chat panel title is a `span`, not a heading |
| [student/history.html](public/student/history.html) | **no h1** → h3 Chat History → h4 No Chat History → h2 Select a Chat → h4 No Chat Selected | 🔴 `<main>` has no `<h1>` at all; h3 precedes h2; h2→h4 skip |
| [student/flagged.html](public/student/flagged.html) | h1 My Flagged Messages | ✅ static OK (audit dynamic flag cards' headings when populated) |
| [student/super-course.html](public/student/super-course.html) | h1 Super Course Chat | 🟡 "Sources" panel title is a styled `div`, not a heading; history panel heading is a `span` inside the toggle button (works for `aria-labelledby` but isn't in the heading outline) |
| [instructor/home.html](public/instructor/home.html) | h1 Home → (hidden-by-default **h4 selected-course-name** inside header) → h2 sections → h3 chart/table titles | 🟡 h1→h4 skip whenever the course selector is open; otherwise clean h1→h2→h3 |
| [instructor/index.html](public/instructor/index.html) (Course Upload) | h1 course title → dynamic unit accordions (h3 in generated markup — verify) | 🟡 if accordion titles are h3, that's h1→h3 skip; modals correctly start at h2 ✅ |
| [instructor/onboarding.html](public/instructor/onboarding.html) | Step 1: h1 Welcome to BiocBot! → h2 How BiocBot Works → **h4 Upload Your Materials / AI Processing / Student Interaction** | 🔴 the exact h2→h4 skip the specialist screenshotted — still present ([lines 97–112](public/instructor/onboarding.html)) |
| | Steps 2–3 (step 1 hidden): **no visible h1** — content starts at h2 "Let's Set Up Your Course" / "Set Up Your First Unit", then h3 → h4 → h5 | 🟠 no h1 on steps 2/3; deep h4/h5 nesting worth simplifying |
| [instructor/settings.html](public/instructor/settings.html) | h1 → h2 group labels/panel titles → h3 sections → h4 items → h5 per-unit transfer | ✅ clean hierarchy, best page in the app |
| [instructor/chat.html](public/instructor/chat.html) | h1 Super Course Chat | ✅ (same span-heading note as student super-course) |
| [instructor/notes.html](public/instructor/notes.html) | h1 → **h3 Browse shared notes / h3 Add a new note** → h2 Write a new note | 🟠 h1→h3 skip; h3 before h2 |
| [instructor/flagged.html](public/instructor/flagged.html) | h1 → h2 Mental Health Concerns | ✅ static OK (verify dynamic cards) |
| [instructor/downloads.html](public/instructor/downloads.html) | h1 → **h3 Error Loading Data / h3 No Students Found** → h2 Students with Saved Chats | 🟠 h1→h3 skip in error/empty states |
| [instructor/student-hub.html](public/instructor/student-hub.html) | h1 → h2 Students → h2 Chat Survey Responses | ✅ |
| [instructor/ta-hub.html](public/instructor/ta-hub.html) | h1 → h2 → h2; modal h2 | ✅ |
| [ta/home.html](public/ta/home.html) | h1 → h2 ×3 → h3 action cards | ✅ |
| [ta/onboarding.html](public/ta/onboarding.html) | h1 Welcome, Teaching Assistant! → **h3 Course Access / Student Support / Instructor Collaboration** → h3 Select Course to Join | 🟠 h1→h3 skip (no h2 on the page) |
| [ta/settings.html](public/ta/settings.html) | h1 → h2 → h2 | ✅ |

Also: [onboarding.html:658-660](public/instructor/onboarding.html) has stray unbalanced closing `</div>`s after the last modal — invalid markup that can confuse the accessibility tree; worth cleaning even though browsers recover.

---

## 3. Modal-by-modal audit

Requirements checklist (from the specialist): trigger is a real `<button>` · focus moves into dialog on open (ideally onto `tabindex="-1"` h2) · `role="dialog"` + accessible name via `aria-labelledby` · focus trapped · Escape closes (except forced-choice dialogs, where Escape must be intercepted while focus is inside) · focus returns to trigger on close.

| Modal | Where | role/name | Focus moved in | Trap | Escape | Focus return | Notes |
|---|---|---|---|---|---|---|---|
| **User agreement** (initial confirmation) | [agreement-modal.js](public/common/scripts/agreement-modal.js) | ❌ generic div, no name | ⚠️ focuses the **whole modal** (`tabindex="-1"` on container, `modalElement.focus()` line 196) — this is the exact run-on-announcement anti-pattern the specialist flagged; his fix (focus the h2 instead) is not implemented | ❌ | ✅-ish: Escape correctly `preventDefault`ed in required mode, closes in read-only mode — but without a trap, focus can leave and then Escape isn't blocked meaningfully | ❌ | The specialist's #1 dialog. Also: `target="_blank"` link with no warning; checkbox before its label visually fine but the "I Agree" button being `disabled` gives no announced reason |
| **Idle timeout** ("Are you still there?") | [idle-timer.js](public/common/scripts/idle-timer.js) + inline copies in [student/index.html:111](public/student/index.html), [dashboard.html:88](public/student/dashboard.html) | ❌ | ❌ nothing focused — a user mid-typing never learns the modal opened; countdown runs silently to sign-out | ❌ | ❌ | ❌ | 🔴 highest-risk modal: screen-reader users can be **signed out without ever being told**. Needs `role="alertdialog"`, focus move, and the countdown region announced once (not per-second) |
| **Confirm reset** | [student/dashboard.html:88](public/student/dashboard.html), dashboard.js | ❌ (has `#modal-title` h2, unused for labelling) | ❌ | ❌ | ❌ | ❌ | |
| **Chat limit info** ("Why the message limit?") | [student-chat-core.js:47](public/student/scripts/student-chat-core.js) | ✅ `role="dialog" aria-modal="true" aria-labelledby` | ❌ | ❌ (`aria-modal` claims a trap that doesn't exist — arguably worse) | ❌ (overlay click only) | ❌ | Scrollable body has `tabindex="0"` + `role="region"` ✅ nice touch |
| **Chat survey** | [student-chat-survey.js:208](public/student/scripts/student-chat-survey.js) | ✅ role, aria-modal, labelledby | ❓ verify (didn't see explicit `.focus()` into it) | ❌ | ✅ Escape closes (line 447) | ❌ | Best-practice starters ✅; stars need checking for keyboard operability + announced values |
| **Topic review** | [topic-review.js:274](public/common/scripts/topic-review.js) | ❌ | ⚠️ focuses the *add-topic input* on open (line 324) — at least focus enters | ❌ | ❌ | ❌ | Close button is "×" unnamed |
| **Question create/edit** | [instructor/index.html:101](public/instructor/index.html) + duplicate in [onboarding.html:459](public/instructor/onboarding.html) | ❌ | ❌ | ❌ | ❌ | ❌ | Opened via `.show` class ([instructor-questions.js:466](public/instructor/scripts/instructor-questions.js)) |
| **Edit learning objective** | instructor/index.html:232, onboarding | ❌ | ❌ | ❌ | ❌ | ❌ | |
| **Auto-link confirmation** | instructor/index.html:264, onboarding | ❌ | ❌ | ❌ | ❌ | ❌ | Yes/No forced choice — if kept non-dismissable, needs the Escape-intercept pattern, not silence |
| **Regenerate AI question** | instructor/index.html:292, onboarding | ❌ | ⚠️ [instructor-ai-generation.js:582](public/instructor/scripts/instructor-ai-generation.js) focuses the feedback textarea after 100ms | ❌ | ❌ | ❌ | |
| **Upload content** | instructor/index.html:329, onboarding:390 | ❌ | ❌ | ❌ | ❌ | ❌ | Long-running upload state swap is silent (no live region) — "do not close this window" text is never announced |
| **Delete unit** (destructive) | instructor/index.html:420 | ❌ | ❌ | ❌ | ❌ | ❌ | Destructive confirm with no focus management is how accidental Enter-presses delete things |
| **Calibration quiz** | instructor/index.html:446 | ❌ | ❌ | ❌ | ❌ | ❌ | Range input has `aria-label` ✅ |
| **Student chat details** | [downloads.html:113](public/instructor/downloads.html) | ❌ | ❌ | ❌ | ❌ | ❌ | |
| **Download progress** | downloads.html:156 | ❌ | ❌ | ❌ | n/a (no close at all — if download hangs, keyboard user is stuck with a visually-blocked page) | ❌ | Progress bar is a styled div, no `role="progressbar"`/values; status text has no live region |
| **Remove TA** (destructive) | [ta-hub.html:78](public/instructor/ta-hub.html) | ❌ | ❌ | ❌ | ❌ | ❌ | |
| **Transfer course review** | [settings.html:1163](public/instructor/settings.html) | ✅ `role="dialog" aria-modal aria-labelledby` + overlay `aria-hidden` | ⚠️ focuses the **Confirm button** (settings.js:1762) — works, but specialist prefers the h2 so users hear the title/context first | ❌ | ✅ Escape closes (settings.js:2017) | ❌ | Closest to correct in the app; loading state swap not announced |

**Summary: 0 of ~18 modals have a focus trap; ~3 have role+name; ~3 handle Escape; 0 restore focus.** Migrating to `<dialog>` + `showModal()` fixes role, trap, Escape, and focus-return in one move — exactly the specialist's recommendation — leaving only "focus the h2 on open" and the agreement modal's Escape-intercept as custom code.

---

## 4. Keyboard access failures (tab order / operability)

Things a keyboard-only user cannot reach or operate. **Tab-through of each page tomorrow should confirm these:**

1. 🔴 **Course Upload accordion headers are click-only `<div>`s.** [instructor-units.js:189, 424-440](public/instructor/scripts/instructor-units.js) — `div.accordion-header` with a click listener; no `role="button"`, no `tabindex`, no keydown, no `aria-expanded`. The entire unit expand/collapse (the core instructor workflow) is mouse-only, and expansion state is unannounced. (Inner buttons — rename, delete, upload — are real `<button>`s ✅, but you can't get the accordion open without a mouse… except via the URL `?unit=` param.)
2. 🔴 **Chat history items are click-only `<div>`s.** [history.js:533](public/student/scripts/history.js) — `div.chat-history-item` with click listener, no `tabindex`/role/keydown. A keyboard user cannot select a past chat, which means Continue/Download/Delete (which only appear after selection) are unreachable too. (The rename input inside *does* handle Enter/Escape ✅ — but you can't reach it.)
3. 🟠 **Home page collapsible sections** — `div.section-header.clickable` with inline `onclick="toggleSection(this)"` ([instructor/home.html:173, 188, 205](public/instructor/home.html)): not focusable, no state. Note the header **contains** a real button (Download) — nested-interactive smell too.
4. 🟠 **Notes hub cards** — `div.hub-card` with `data-target` click switching Browse/Add panels ([instructor/notes.html:59-68](public/instructor/notes.html)): not focusable. These are effectively tabs; minimum fix is `<button>`s, ideal is a tabs pattern.
5. 🟠 **Download dropdown menus** ([downloads.html:93-101](public/instructor/downloads.html), downloads.js) — `toggleDownloadMenu()` toggles a `div` menu: trigger has no `aria-expanded`/`aria-haspopup`, no Escape-to-close, no arrow-key behavior; verify whether it even closes on blur.
6. 🟡 **Persistence topic cards** ([home.js:2833](public/instructor/scripts/home.js)) get `role="button" tabindex="0"` ✅ — **verify a keydown (Enter/Space) handler actually exists**; role+tabindex without keydown is a common half-fix. Same check for the quiz MC `label.option-label` pattern (radios inside labels — native, should be fine ✅).
7. ✅ **TA course cards** ([ta-home.js:539](public/ta/scripts/ta-home.js)): `role="button" tabindex="0" aria-pressed` and the file has a keydown listener — good model to point at.
8. 🟡 **"Set Up One of Your Sections" link styled as button** ([instructor/home.html:83](public/instructor/home.html)) — fine semantically (it navigates), but check focus style.
9. 🟡 Logout / "View Chat Rules" / TA "Course Upload"/"Student Flag" are `<a href="#">` acting as buttons — they work with Enter but not Space, and "#" pollutes history/scrolls to top. Prefer `<button>`.

**Tab-order smoke test script for tomorrow (per page):** load page → Tab (should hit skip link first — currently won't) → through sidebar → into main in visual order → open each modal via keyboard → Tab inside (should cycle within) → Escape → focus should be back on trigger. Log every deviation here.

---

## 5. Forms & labelling issues

1. 🟠 **Login error/status messages are not announced.** [login.js `showMessage()`](public/common/scripts/login.js) swaps text into `#message` and un-hides the container — no `role="alert"`/live region. A blind user submitting bad credentials hears nothing. (Contrast: onboarding `field-feedback` uses `role="alert"` ✅.)
2. 🟠 **Chat responses may not be announced** — `#chat-messages` has no `aria-live`; only a status element ([student-chat-core.js:373](public/student/scripts/student-chat-core.js)) is live. Verify with VoiceOver: does the bot's reply get read out when it arrives? If not, this is the single most impactful chat fix (a live region wrapper or per-message `role="log"` container).
3. 🟡 **Label text without `for`/control association:** "Set Up One of Your Sections:" ([home.html:81](public/instructor/home.html)) labels a link; "Correct Answer" / "Answer Options" group labels in question modals are bare `<label>`s not tied to the radio groups (should be `<fieldset>/<legend>` or `role="group"` + `aria-labelledby`). Same for quiz TF options.
4. 🟡 **Placeholder-only fields:** notes title + body ([notes.html:90-94](public/instructor/notes.html)), tag input, topic-review add-topic input, MCQ option inputs ("Option A"… placeholders only, [instructor/index.html:179-204](public/instructor/index.html)). Placeholders disappear on input and aren't reliable names.
5. 🟡 **`title` as the only name:** `#upload-topic-unit-select` (`title="Topic unit"`), New Session button relies on visible text ✅ but `#shuffle-btn`, refresh buttons etc. use `title` for extra context that AT users may miss — fine, but ensure the visible text is self-sufficient.
6. 🟡 **"Email (Not optional)"** on registration ([index.html:67](public/index.html)) — label says not-optional but the input lacks `required`; confusing for everyone, inconsistent for AT.
7. 🟡 **Charts and visual data:** the weekly struggle Chart.js `<canvas>` ([home.html:231](public/instructor/home.html)) has no `role="img"`, no `aria-label`, no text alternative/table fallback. Mode-distribution bars and all progress bars (`.progress-fill` divs in quiz, onboarding, downloads) lack `role="progressbar"` + `aria-valuenow/min/max`; the quiz's `#progress-text` ✅ at least exists as text.
8. 🟡 **Table headers**: live-struggle table uses `<thead><th>` ✅ but no `scope="col"` (minor).
9. 🟡 **`aria-live` on large containers**: `super-course-pool-panel` and history list are `aria-live="polite"` on whole panels — re-rendering the full list will re-announce everything. Consider scoping live regions to status lines only.

---

## 6. Positives to show the specialist ✅

Evidence the recommendations are landing (all added since his last review, worth demoing):

- [settings.html](public/instructor/settings.html): clean h1→h2→h3→h4 hierarchy; `tabindex="-1"` panel titles that receive focus on rail navigation ([settings.js:106](public/instructor/scripts/settings.js)) — his exact focus-the-heading pattern; `aria-labelledby`/`aria-describedby` on every control; `:focus-visible` styles; `aria-current` on rail links; transfer modal with role/name/Escape.
- [notifications.js](public/common/scripts/notifications.js): `role="status"` live region, labeled dismiss buttons.
- Super-course history toggle: real `<button>` with `aria-expanded` + `aria-controls`, updated in JS ([super-course.js:632](public/student/scripts/super-course.js)) — the pattern the mobile toggle should copy.
- Chat survey + chat-limit modals carry `role="dialog"`/`aria-modal`/`aria-labelledby`; survey closes on Escape.
- TA course cards: `role="button"`, `tabindex="0"`, `aria-pressed`, keydown handling.
- `role="alert"` on inline form errors; `role="status"` on academic sync; `aria-label` on icon-only send button; `aria-label` on the calibration range input and MH status filter.
- Struggle-topic panel in the question modal uses `<details>/<summary>` ✅.
- Existing axe CI suite under [tests/a11y/](tests/a11y/) with per-role storage states, modal-scoped scans, and animation freezing.

---

## 7. Testing gaps & recommended additions

Current automated coverage ([tests/a11y/axe-helper.js](tests/a11y/axe-helper.js)) runs axe WCAG A/AA but **only fails on critical/serious impacts** — `heading-order` is *moderate* in axe, so every skipped-heading issue in §2 is currently warn-only noise in CI. Per the a11yproject article, this suite structurally cannot catch the §3/§4 findings (focus traps, Escape, tab order, announcements).

Tests the specialist explicitly asked for, none of which exist yet:

1. **Heading-hierarchy test** (his spec, verbatim): collect all headings (`h1–h6` + `[role="heading"][aria-level]`), excluding hidden ones (`hidden`, `inert`, `aria-hidden="true"`, `display:none`/`visibility:hidden` incl. inherited, inside closed `details`/`dialog`/popover) → build hierarchy → assert no skipped levels; `<main>` starts at h1. Extend to run inside each open modal asserting it starts at h2.
2. **Modal keyboard tests** per modal: opens via keyboard from a `<button>` trigger; focus lands inside (on the h2); Tab cycles within (assert `document.activeElement` never leaves the dialog); Escape closes (or is correctly swallowed for the agreement modal while focus is inside); focus returns to trigger.
3. **Skip-link test**: first Tab on every page lands on the skip link; activating it moves focus to `#main`.
4. **Tab-order test**: tab sequence on each page matches visual order; every item in §4 reachable.
5. Ratchet `BLOCKING_IMPACTS` to include moderate once §2 is fixed, so `heading-order` regressions block PRs.

Manual pass still required (axe can't): VoiceOver run of the chat flow (Q2 in §5 — are bot replies announced?), idle-timeout announcement, focus-indicator contrast (3:1), zoom/reflow at 400%, `prefers-reduced-motion` on spinners/transitions.

---

## 8. Priority order (suggested agenda for tomorrow)

1. **Idle-timeout modal** (§3) — silent auto-signout is the worst user harm.
2. **Convert shared modal template to `<dialog>`** — one pattern, ~18 dialogs fixed for role/name/trap/Escape/focus-return; add focus-the-h2 + agreement-modal Escape intercept on top.
3. **Skip link + `id="main"`/`tabindex="-1"` h1s on all pages** (§1.1) — small, high-impact, page-template-level.
4. **Keyboard-inaccessible core flows**: unit accordion (§4.1), chat history selection (§4.2).
5. **Unnamed controls**: mode toggle, publish toggles, mobile header toggle (+`aria-expanded`), "×" close buttons.
6. **Heading fixes** (§2) — mostly mechanical tag swaps; fixes the specialist's screenshotted onboarding case.
7. `aria-current="page"` in the shared sidebar; `<aside>`→`<header>`.
8. Announcements: login errors, chat replies, loading/empty/error state live regions.
9. Tooltips → focusable disclosures; charts/progress bars alternatives.
10. Add the heading + modal keyboard tests (§7) so it stays fixed.
