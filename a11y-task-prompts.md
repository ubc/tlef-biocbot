# A11y fix prompts — delegate to smaller models

Run in this order. Tasks 1–6 are independent of each other. Task 7 (modal helper) must land before 8–10. Tasks 11–13 anytime. Task 14 (tests) last.

Paste the **General rules** block at the top of every prompt.

---

## General rules (prepend to every task)

```
Rules for this task:
- Read the file audits.md at the repo root first — it is the accessibility audit this task comes from. Only address the section named in this task.
- Do NOT change visual appearance. When changing an element's tag (e.g. div→button, h3→h2), add/keep CSS classes so it renders identically (reset button default styles: background:none; border:none; font:inherit; text-align:inherit; padding as before).
- Do NOT refactor, rename, or "clean up" anything beyond the described change.
- All pages share the same sidebar/modal template — apply identical changes to every listed file, don't skip any.
- After editing, verify with grep that every listed file was changed, and open no dev server.
```

---

## Task 1 — Skip links + main-content focus targets (audits.md §1.1)

```
Add a skip link to every app page in public/.

Files: public/student/index.html, dashboard.html, flagged.html, history.html, quiz.html, super-course.html; public/instructor/index.html, home.html, chat.html, notes.html, flagged.html, downloads.html, ta-hub.html, settings.html, onboarding.html, student-hub.html; public/ta/home.html, onboarding.html, settings.html.

For each file:
1. As the FIRST element inside <body> (before .app-container), insert:
   <p class="skip-link"><a href="#main">Skip to main content</a></p>
2. Find the page's <h1> inside <main>. Add id="main" and tabindex="-1" to it. If the id "main" is already used elsewhere on that page, report it instead of guessing.
   Special cases:
   - public/student/history.html has no h1 in main. Add one: <h1 id="main" tabindex="-1" class="visually-hidden">Chat History</h1> as the first child of <main>, and demote nothing else (heading fixes are a separate task).
   - public/instructor/onboarding.html has an h1 only inside #step-1. Put id="main" tabindex="-1" on that h1; ALSO add id="main" nowhere else.
3. In public/styles/style.css add once:
   .skip-link { position: fixed; inset-inline-start: -100%; top: 0; z-index: 10000; margin: 0; }
   .skip-link a { display: inline-block; padding: 10px 16px; background: #fff; color: #0055b7; border: 2px solid #0055b7; border-radius: 0 0 6px 0; }
   .skip-link a:focus-visible { position: fixed; inset-inline-start: 0; top: 0; }
   .skip-link:focus-within { inset-inline-start: 0; }
   .visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
4. Do not add a skip link to public/index.html (login) — it has no <main>; skip it.

Verify: grep -L 'class="skip-link"' over the 19 files returns nothing; grep 'id="main"' shows exactly one per file.
```

## Task 2 — Sidebar landmark + aria-current (audits.md §1.2, §1.3)

```
Two mechanical changes across all app pages (same 19 files as the skip-link task; the sidebar markup is nearly identical in each).

1. Change <aside class="sidebar"> ... </aside> to <header class="sidebar"> ... </header> in every file. Update any CSS selectors in public/styles/*.css and public/instructor/styles/*.css, public/ta/styles/*.css, public/student CSS that reference "aside.sidebar" or bare "aside" (grep first; if a selector is just ".sidebar" leave it alone).
2. In each sidebar nav, the current page's <li> has class="active". On that li's <a>, add aria-current="page". Keep the class as-is. Note: some pages toggle .active via JS (public/instructor/scripts/settings.js adds aria-current to rail links already — leave that file alone). For nav items whose active class is set dynamically in JS (search for classList.add('active') in public/**/scripts/*.js targeting sidebar links), also set setAttribute('aria-current','page') beside the classList.add and removeAttribute beside classList.remove.

Verify: grep '<aside class="sidebar"' returns nothing; each page's active nav link has aria-current="page".
```

## Task 3 — Small named-control fixes (audits.md §1.4, §1.6, §1.7)

```
Three small fixes.

1. public/common/scripts/mobile-layout.js: the created button.mobile-header-toggle needs:
   - toggleBtn.setAttribute('aria-label', 'Toggle navigation menu');
   - toggleBtn.setAttribute('aria-expanded', String(!document.body.classList.contains('mobile-collapsed')));
   - In the click handler, after toggling, set aria-expanded to String(!isCollapsed).
   - Add aria-hidden="true" on the ▲/▼ span in both places it's written.
2. Modal close buttons: every <button class="modal-close" ...>×</button> across public/**/*.html and in JS template strings (public/common/scripts/topic-review.js). Add aria-label="Close" to each, and wrap the × as <span aria-hidden="true">×</span>. Also do this for button.quiz-chat-close in public/student/quiz.html and the chat-survey close button in public/student/scripts/student-chat-survey.js if it lacks a label (it already has aria-label — leave it).
3. Unnamed toggle checkboxes:
   - public/student/index.html: #mode-toggle-checkbox — add aria-label="Chat mode: Tutor when on, Protégé when off" to the input (keep the empty label element for styling).
   - public/instructor/scripts/instructor-units.js (~line 200): the publish checkbox template <input type="checkbox" id="publish-${unitId}" ...> — add aria-label="Publish ${unitName} to students" inside the template string.

Verify: grep -rn 'class="modal-close"' public | grep -v aria-label returns nothing.
```

## Task 4 — Heading hierarchy fixes (audits.md §2 — table lists every skip)

```
Fix skipped heading levels. Change tags only; if a heading's size visibly comes from the tag, add a class and a CSS rule that pins the old font-size/weight so nothing changes visually. Check each page's CSS for existing h2/h3/h4 rules that would restyle the changed element.

1. public/instructor/onboarding.html: the three <h4> in .workflow-step (Upload Your Materials / AI Processing / Student Interaction) → <h3>. (This is the specialist's screenshotted issue.)
2. public/student/dashboard.html: the two <h3> in .summary-card → <h2>.
3. public/student/quiz.html: <h4>Review Materials</h4> → <h2>. Also wrap "Need help understanding this?" (span.quiz-chat-title) as <h2 class="quiz-chat-title">.
4. public/student/history.html: reorder levels — <h3>Chat History</h3> → <h2>; <h4>No Chat History</h4> → <h3>; <h2 id="preview-title"> stays; <h4>No Chat Selected</h4> → <h3>.
5. public/instructor/notes.html: the two <h3> in .hub-card → <h2>.
6. public/instructor/downloads.html: <h3>Error Loading Data</h3> and <h3>No Students Found</h3> → <h2>.
7. public/ta/onboarding.html: the three <h3> in .feature-card and <h3>Select Course to Join</h3> → <h2>.
8. public/instructor/home.html: <h4 id="selected-course-name"> → <h2 id="selected-course-name" class="selected-course-name-heading"> with CSS pinning previous h4 size.
9. public/instructor/onboarding.html steps 2 & 3 have no h1 when step 1 is hidden: change <h2>Let's Set Up Your Course</h2> and <h2>Set Up Your First Unit</h2> to <h1 class="step-title">, then demote their descendants one level each (h3→h2, h4→h3, h5→h4 within #step-2 and #step-3 only), pinning styles with classes as needed. Do NOT touch the modals' headings at the bottom of the file.

After each file, list its final heading outline in your summary so it can be reviewed. Verify no page's <main> jumps a level.
```

## Task 5 — Live regions & announcements (audits.md §5.1, §5.2, §1.11)

```
1. public/index.html + public/common/scripts/login.js: give the login message container role="alert". In index.html change <div id="message" class="message"></div> to <div id="message" class="message" role="alert"></div>. No JS change needed (textContent swap into an existing alert region announces).
2. public/student/index.html and public/student/super-course.html and public/instructor/chat.html: add role="log" and aria-live="polite" and aria-relevant="additions" to the <div class="messages" id="chat-messages"> element so incoming bot messages are announced.
3. Loading→content swaps: add role="status" to these existing elements (attribute only, no restructure):
   - public/student/dashboard.html: both .loading-spinner divs
   - public/student/quiz.html: #quiz-loading
   - public/instructor/downloads.html: #loading-state, and #download-status inside the download modal
   - public/student/flagged.html + public/instructor/flagged.html: #loading-state
   - public/instructor/index.html upload modal + public/instructor/onboarding.html upload modal: #upload-loading-indicator
4. Idle countdown: in public/common/scripts/idle-timer.js template AND the inline copies in public/student/index.html and public/student/dashboard.html, add role="status" to the modal-body div that contains the countdown text (announces once when shown; the per-second span update inside stays aria-live-inherited — acceptable).

Verify with grep that every listed element has the attribute.
```

## Task 6 — Tooltips, emoji, charts, progress bars (audits.md §1.8, §1.10, §5.7)

```
1. Hover-only tooltips in public/instructor/home.html (.info-icon.tooltip spans with data-tooltip):
   - Change each span to <button type="button" class="info-icon tooltip" data-tooltip="..." aria-label="More information">ℹ️</button> — wait: instead put the emoji in <span aria-hidden="true">ℹ️</span> inside the button.
   - In public/styles/home.css: extend the reveal rules `.tooltip:hover::after, .tooltip:hover::before` to also match `.tooltip:focus-visible::after, .tooltip:focus-visible::before`. Add `.info-icon { background:none; border:none; font:inherit; cursor:help; }` reset so the button looks like the old span.
   - Note some of these buttons sit inside div.section-header elements that have onclick — add event.stopPropagation() is NOT needed since a separate task converts those; just ensure type="button".
2. Decorative emoji in headings: in public/instructor/home.html and public/instructor/onboarding.html, wrap emoji that start heading text (🎓 📊 🧭 📈 ⚠️ ✅ 📋 🎉) in <span aria-hidden="true">…</span>. Same for the 📁 📝 icons inside upload method buttons in public/instructor/index.html and the ⚠️ warning-icon div in the delete-unit modal.
3. Chart canvas: public/instructor/home.html #weekly-struggle-chart — add role="img" and aria-label="Bar chart of weekly active struggle counts by topic. Data table not available; use the Download CSV button for the underlying data."
4. Progress bars — add role="progressbar" with labels:
   - public/student/quiz.html .progress-bar div: role="progressbar" aria-labelledby="progress-text" (JS task: in public/student/scripts/quiz.js where progress-fill width is set, also set aria-valuenow/aria-valuemin="0"/aria-valuemax on the .progress-bar element).
   - public/instructor/onboarding.html .progress-bar: role="progressbar" aria-label="Onboarding progress" and same valuenow wiring in public/instructor/scripts/onboarding-flow.js where progress-fill width is updated.
   - public/instructor/downloads.html download modal .progress-bar: role="progressbar" aria-label="Download progress", wired where width is set in downloads.js.
5. public/instructor/home.html live-struggle table: add scope="col" to the four <th>.
```

## Task 7 — Shared modal a11y helper (audits.md §1.5, §3) — PREREQUISITE for tasks 8–10

```
Create public/common/scripts/modal-a11y.js implementing one reusable function, no framework:

window.a11yModal = {
  open(modalRootEl, { labelledBy, initialFocus, escapable = true, onRequestClose } = {}) → void,
  close(modalRootEl) → void
}

Requirements for open():
- Ensure role="dialog" and aria-modal="true" on the dialog element (modalRootEl itself if it's the dialog box, else its .modal-content / first element child — accept an options.dialogEl override).
- Accessible name: if labelledBy id given, set aria-labelledby. Else find the first h1–h6 inside; if it lacks an id, generate one (modal id + "-title"); set aria-labelledby to it.
- Focus: if initialFocus element/selector given, focus it. Else focus the first heading after giving it tabindex="-1". Store document.activeElement before opening as the restore target (WeakMap keyed by modalRootEl).
- Focus trap: keydown listener on the modal root; on Tab/Shift+Tab compute visible, enabled focusables (a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"]), filtered by offsetParent !== null) and wrap at the ends.
- Escape: if escapable, on Escape call onRequestClose() if provided else close(). If NOT escapable, preventDefault+stopPropagation on Escape while focus is within the modal.
close():
- Remove listeners, restore focus to the stored trigger element if it's still in the document.
The helper must not show/hide the modal itself — callers keep their existing display/.show logic and call these alongside.

Then add <script src="...common/scripts/modal-a11y.js"></script> BEFORE the other page scripts in every HTML page that contains a modal: public/student/index.html, dashboard.html, quiz.html (no modal but quiz-chat panel — skip), public/instructor/index.html, onboarding.html, downloads.html, ta-hub.html, settings.html, and pages loading agreement-modal.js or idle-timer.js (student/index.html, student/history.html, student/quiz.html, student/flagged.html). Adjust relative paths per directory depth.

Do not wire any modal yet — that's the next tasks. Verify the file loads without errors by checking syntax with node --check.
```

## Task 8 — Wire helper into instructor modals (audits.md §3 rows: question, learning-objective, auto-link, regenerate, upload, delete-unit, calibration, student-details, download-progress, remove-TA)

```
Prerequisite: public/common/scripts/modal-a11y.js exists (window.a11yModal.open/close).

Wire every open/close function pair to the helper. For each openXxxModal()/closeXxxModal() pair, after the existing show line (classList.add('show') or style.display change) add:
  a11yModal.open(modal, { onRequestClose: closeXxxModal });
and at the top of the close function add: a11yModal.close(modal);

Files and functions (grep for the exact names):
- public/instructor/scripts/instructor-questions.js: openQuestionModal/closeQuestionModal, openQuestionLearningObjectiveModal/close..., openAutoLinkConfirmationModal/close...
- public/instructor/scripts/instructor-ai-generation.js: regenerate modal open/close (keep its existing textarea focus by passing initialFocus: '#regenerate-feedback').
- public/instructor/scripts/instructor-documents.js + public/instructor/scripts/onboarding-upload.js: openUploadModal/closeUploadModal.
- public/instructor/scripts/instructor-units.js: openDeleteUnitModal/closeDeleteUnitModal, calibration modal open/close if present (grep openCalibrationModal).
- public/instructor/scripts/downloads.js: viewStudentSessions' modal show (#student-modal, style.display='block') and closeStudentModal; the download progress modal (#download-modal) — open with { escapable: false } since it has no close controls.
- public/instructor/scripts/ta-hub.js: the #remove-ta-modal show/hide (classList add/remove 'show').
- public/student/scripts/dashboard.js: the #confirm-modal (style.display='flex') and its hide path.
- public/common/scripts/topic-review.js: its modal open (keep existing input focus via initialFocus).

Duplicated modals in public/instructor/onboarding.html use the same functions — no extra work.
Do not change any modal HTML. Do not alter existing focus() calls except via initialFocus as noted. node --check every edited file.
```

## Task 9 — Agreement modal + idle-timeout modal (audits.md §3 first two rows)

```
Prerequisite: modal-a11y.js helper.

A) public/common/scripts/agreement-modal.js:
1. In createModal(), on <div class="agreement-modal" id="agreement-modal" tabindex="-1">: remove tabindex="-1"; add role="dialog" aria-modal="true" aria-labelledby="agreement-modal-title". Give the h2 id="agreement-modal-title" and tabindex="-1".
2. In show(): replace modalElement.focus() with:
   a11yModal.open(this.modal, { dialogEl: this.modal.querySelector('#agreement-modal'), labelledBy: 'agreement-modal-title', initialFocus: '#agreement-modal-title', escapable: this.isReadOnly === true, onRequestClose: () => this.hide() });
   Note: show() can be called with different readOnly values, so open must be called per-show (helper re-open on same element must be safe — if not, fix the helper to tear down before re-adding).
3. In hide(): call a11yModal.close(this.modal) first.
4. Remove the class's own document-level Escape listener (the helper now owns Escape both ways).
5. On the academic-integrity link (target="_blank"), append <span class="visually-hidden"> (opens in new tab)</span>.

B) public/common/scripts/idle-timer.js (and the inline modal copies in public/student/index.html and public/student/dashboard.html must stay in sync — idle-timer.js skips injection if #idle-timeout-modal exists, so edit the HTML copies too):
1. On div.modal-content inside #idle-timeout-modal: role="alertdialog" aria-modal="true" aria-labelledby="idle-modal-title" aria-describedby="idle-modal-desc". Give the h2 id="idle-modal-title" tabindex="-1", and the modal-body id="idle-modal-desc".
2. Where the modal is shown (grep style.display = 'flex' or similar in idle-timer.js), call a11yModal.open(modal, { initialFocus: '#idle-stay-btn', escapable: false }). Focus the Stay button (not the h2) because Enter must map to the safe action.
3. Where hidden, call a11yModal.close(modal).
node --check both JS files.
```

## Task 10 — Keyboard access for click-only widgets (audits.md §4.1–§4.5)

```
Four independent fixes. Preserve visuals via CSS resets (see General rules).

1. public/instructor/scripts/instructor-units.js — accordion headers (template around line 189, listener around line 424):
   Keep div.accordion-header as container, but wrap the title area's clickable role into the header via: give the header role="button", tabindex="0", aria-expanded (true when its .accordion-content lacks .collapsed, kept in sync in the toggle handler), and add a keydown handler (Enter and Space → same toggle, Space with preventDefault). The existing guard that ignores clicks on .publish-toggle must also apply to keydown targets. Simpler alternative if the header contains no other text than title+buttons: leave as is per above (converting to <button> would illegally nest the rename/delete buttons — do NOT do that).
2. public/student/scripts/history.js — createHistoryItem (line ~533): on the item div add role="button", tabindex="0", and keydown Enter/Space → same handler as click. Also set aria-current="true" on the selected item and remove from others where the selection class is toggled.
3. public/instructor/home.html + public/instructor/scripts/home.js — div.section-header.clickable with onclick="toggleSection(this)": add role="button" tabindex="0" aria-expanded="true" to each such div in the HTML, and in home.js add one delegated keydown listener that triggers toggleSection on Enter/Space for [role="button"].section-header, updating aria-expanded in toggleSection. The download button inside one header already stops propagation — keep that.
4. public/instructor/notes.html + public/instructor/scripts/notes.js — hub cards: change the two div.hub-card to <button type="button" class="hub-card" ...> keeping ids/data-target. Add to public/styles/notes.css: .hub-card { background:...; border:...; font:inherit; text-align:inherit; display:block; width:100%; cursor:pointer; } matching current computed appearance (copy existing .hub-card rules; only add resets that a button needs). Verify notes.js listeners select by class/id, not tag.
5. public/instructor/scripts/downloads.js — toggleDownloadMenu(): set aria-expanded and aria-haspopup="menu" on the toggle button (all toggles are real buttons already), close the open menu on Escape (returning focus to its toggle) and on focusout leaving the dropdown container.
6. Verify public/instructor/scripts/home.js persistence-topic cards (role="button" tabindex="0", line ~2833) actually have a keydown handler; if not, add Enter/Space handling next to their click binding.
```

## Task 11 — Form labelling (audits.md §5.3–§5.6)

```
1. Radio group labelling in the question modals (public/instructor/index.html AND public/instructor/onboarding.html — duplicated markup):
   - "Correct Answer" true/false section: wrap div.radio-group's label+options in <fieldset class="radio-group-fieldset"><legend class="form-label-legend">Correct Answer</legend>…</fieldset>, removing the bare <label>. Add CSS: fieldset.radio-group-fieldset { border:0; padding:0; margin:0; } .form-label-legend { padding:0; } styled like the old label (copy its rule).
   - Same for "Answer Options" MCQ section.
   - public/student/quiz.html #tf-options: wrap in fieldset/legend "Answer" (legend can be class="visually-hidden").
2. MCQ option inputs (Option A–D placeholders): add aria-label="Option A text" etc. to the four .mcq-input inputs in both files.
3. public/instructor/notes.html: add visually-hidden <label for="note-title">Note title</label> and <label for="note-body">Note body</label>; add aria-label="Add tag" to #tag-input.
4. public/instructor/index.html + onboarding.html: #upload-topic-unit-select — add aria-label="Unit for new topic" (keep title).
5. public/index.html: "Email (Not optional)" — add required to #reg-email so label and behavior agree.
6. public/instructor/home.html line ~81: change <label>Set Up One of Your Sections:</label> to <p class="form-label-text">Set Up One of Your Sections:</p> with CSS matching the label styling in that block.
```

## Task 12 — Onboarding stray markup (audits.md §2 last note)

```
public/instructor/onboarding.html lines ~658-660 contain stray closing tags after the last modal (regenerate-modal):
        </div>
    </div>
</div>
Determine the correct structure by matching every opening div from <body> down (the app-container/main structure closes before the modals; each modal div must balance itself). Remove only the unbalanced extra closers so the document validates. Verify by parsing: node -e with a simple tag-balance count, or paste through `npx htmlhint` if available offline. Report the before/after tag balance.
```

## Task 13 — Settings-style focus-visible pass (audits.md §1.9)

```
Add a consistent visible focus indicator without redesigning:
In public/styles/style.css add at the end:
  a:focus-visible, button:focus-visible, [role="button"]:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible, summary:focus-visible {
    outline: 3px solid #0055b7; outline-offset: 2px; border-radius: 2px;
  }
Then grep all css files under public/ for "outline: none" and "outline:none" — for each hit, either delete it or ensure a :focus-visible replacement with ≥3:1 contrast exists for that element; list every hit and what you did in your summary. Do not otherwise restyle. (public/styles/settings.css already has good :focus-visible rules — leave them.)
```

## Task 14 — Automated tests (audits.md §7) — do LAST

```
Add two Playwright specs under tests/a11y/, following the conventions in the existing specs there (storage states from ../e2e/helpers/users, base config, axe-helper patterns).

1. tests/a11y/heading-hierarchy.a11y.spec.js:
   - Helper getVisibleHeadings(page, root?) evaluated in-page: query h1,h2,h3,h4,h5,h6,[role="heading"][aria-level], exclude any element (or ancestor-of) with hidden, inert, aria-hidden="true", computed display:none or visibility:hidden, or inside a closed <details>/<dialog>/[popover]:not(:popover-open).
   - For each page already visited by the existing specs (reuse their URL lists — grep the spec files for page.goto calls and copy the list + matching storageState), assert: first heading within main is level 1, and walking the full-page list, each heading's level is at most previous+1 (no skips). Headings before <main> may start at 2.
   - Mark currently-failing pages with test.fixme() referencing audits.md §2 so the suite is green until fixes land, then flips.
2. tests/a11y/modal-keyboard.a11y.spec.js:
   - For three representative modals — student dashboard #confirm-modal, instructor #question-modal (Course Upload page), ta-hub #remove-ta-modal — test: open via keyboard (focus trigger, press Enter); expect document.activeElement inside the modal; press Tab 20 times and assert activeElement stays inside; press Escape and assert modal hidden and focus returned to the trigger. Use test.fixme() on any that fail today, referencing audits.md §3.
Run: npx playwright test -c playwright.a11y.config.js tests/a11y/heading-hierarchy.a11y.spec.js — if the webServer can't start in your environment, report that instead of faking results.
```
