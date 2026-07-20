# BiocBot accessibility audit — round 2

**Date:** 2026-07-20
**Audited revision:** `833ea14` (`ivan_edit`)
**Scope:** All 20 HTML files under `public/`, role-specific dynamic UI, modal/focus helpers, and `tests/a11y/`.
**Implementation changes in this pass:** none. Only this audit and `a11y-task-prompts.md` were updated.

## Executive result

The first remediation round made substantial, verifiable progress. Skip links, main-focus targets, heading corrections, current-page state on most navigation, accessible chat logs, modal close names, a shared focus-trap helper, and a heading regression test now exist.

The product is **not yet ready to describe as fully keyboard- or screen-reader-accessible**. The remaining risk is concentrated in stateful UI that axe does not exercise: several modal implementations bypass the helper, onboarding changes screens without moving the skip target or focus, some disclosure fixes introduced nested interactive controls, and important quiz feedback is not announced.

Automated result from this audit:

```text
83 tests discovered
78 passed
4 skipped
1 failed
```

The one live failure is a WCAG 1.4.3 contrast failure in the instructor Flagged Content error state: `#ef4444` on `#ffffff`, 3.76:1 where 4.5:1 is required. The four skips are not harmless: they suppress `/student` and `/student/history` heading checks plus two modal keyboard tests.

## Method and limits

- Re-checked every claim from the first audit against the current tree instead of carrying it forward.
- Ran the full Playwright/axe suite with the repository's authenticated fixtures.
- Inspected the dynamic states and event handlers that page-level axe scans cannot reach.
- Used the login UI in a browser to verify the sign-in/register view transition. Activating “Create one” hides one form and shows the other, but focus falls to `<body>` rather than the new heading or first field.
- Followed Nat Tarnoff's manual-audit sequence: understand mouse behavior, run automatics, then review keyboard, screen-reader naming/announcements, contrast, reading level, and WCAG criteria. See [A11y 101: How to test manually](https://tarnoff.info/2025/05/15/a11y-101-how-to-test-manually/).
- This was not a real VoiceOver/NVDA listening session and did not include a completed 400% zoom/reflow, forced-colors, or focus-indicator contrast pass. Those are explicitly listed as meeting checks below; source inspection cannot honestly certify them.

Severity: **P0** blocks or silently disrupts a core flow; **P1** serious barrier; **P2** moderate/quality issue; **Verify** requires hands-on AT/visual testing.

## Confirmed improvements since round 1

| Area | Round-two status |
|---|---|
| Skip links and main targets | ✅ Present exactly once on all 19 application pages; sidebar is now `<header class="sidebar">`. |
| Headings | ✅ Previously reported static skips are corrected, including instructor onboarding h2→h4. The current heading test passes every route it runs. |
| Current-page navigation | ✅ Present on most pages. Two Settings-page omissions remain below. |
| Mobile navigation toggle | ✅ Has a useful label, hidden arrow glyph, and updated `aria-expanded`. `aria-controls` is still absent. |
| Modal close buttons | ✅ `.modal-close` controls now use `aria-label="Close"` and hide the multiplication glyph. |
| Toggle names | ✅ Student Tutor/Protégé mode and unit publish checkboxes now have accessible names. |
| Chat announcements | ✅ Student, instructor, and Super Course main message lists use `role="log" aria-live="polite" aria-relevant="additions"`. |
| Login errors | ✅ The message element now uses `role="alert"`; registration email is `required`. |
| Visual data | ✅ The weekly chart has a text alternative; quiz/onboarding/download progress bars now expose programmatic values while updating. |
| Keyboard reachability | ✅ Student saved-chat selection, main unit accordions, instructor home section headers, dropdown state, and persistence topic cards received keyboard support. Caveats below. |
| Shared modal behavior | ✅ `modal-a11y.js` provides focus entry, Tab containment, Escape policy, and focus restoration. The tested dashboard confirmation passes. Not all dialogs call it. |
| Regression tests | ✅ Heading and modal-keyboard specs now exist. They remain incomplete/skipped as detailed below. |

## Remaining findings

### R2-01 — P0: multiple modal families still bypass the shared keyboard contract

The shared helper is only useful where every open and close path calls it. These modal families do not:

- Instructor onboarding question, learning-objective, auto-link, and regenerate dialogs only add/remove `.show` in `onboarding-objectives-questions.js` and `onboarding-ai-generation.js`.
- Student chat-limit dialog has role/name but no focus entry, trap, Escape handling, or return (`student-chat-core.js:37-95`).
- Student chat survey has role/name and a document-level Escape handler, but no focus entry, trap, or return (`student-chat-survey.js:190-215, 382-450`).
- Instructor topic-to-unit dialog has no dialog role/name, starts at h3, and has no focus management or Escape (`home.js:2936-3000`).
- Extracted-question review has no role/name, no initial focus, no trap, no Escape, and no focus return (`instructor-questions.js:1485-1583`). Its “×” close button is also unnamed.
- Document preview has role/name, focuses Close, handles Escape, and manually returns focus, but does not trap focus (`instructor-documents.js:915-1046`).
- Settings course-copy review has role/name and Escape, but focuses the confirm button, does not trap, and does not restore its trigger (`settings.js:1696-1792, 2046-2050`).

The helper is a custom simulation over `<div>`s, not native `<dialog>`. Even where it works, background content is not made `inert`; `aria-modal` alone does not physically prevent all virtual-cursor/background interaction. The specialist's recommendation to prefer `<dialog>.showModal()` remains the safer end state.

**Reproduce:** Open each dialog with Enter; note where focus remains behind it. Press Tab repeatedly, Shift+Tab, then Escape; close and check whether focus returns to the exact trigger.

**WCAG:** 2.1.1 Keyboard, 2.1.2 No Keyboard Trap, 2.4.3 Focus Order, 3.2.1 On Focus, 4.1.2 Name/Role/Value.

### R2-02 — P1: onboarding screen changes break the skip target and do not announce context

Instructor onboarding puts `id="main" tabindex="-1"` only on the step-1 h1. Steps 2, 3, and the completion state have different h1s. `showStep()` swaps `.active` without moving focus or transferring the stable target (`onboarding-flow.js:336-381`). Once step 1 is hidden, the skip link still points to a hidden heading.

TA onboarding has the same completion-state issue: the initial h1 owns `#main`, then the entire step is hidden and a different h1 appears.

**Reproduce:** Activate Get Started, then invoke the skip link or inspect `#main`; focus/context remains tied to hidden step 1. Resume an instructor directly at step 3 and observe that no focus announcement identifies the screen.

**WCAG:** 2.4.1 Bypass Blocks, 2.4.3 Focus Order, 2.4.6 Headings and Labels.

### R2-03 — P1: TA completion redirects after five seconds with no user control

`showTAOnboardingComplete()` shows a success screen and unconditionally navigates to `/ta` after 5 seconds (`ta-onboarding.js:249-262`). A screen-reader, magnification, cognitive, or switch user may not have time to read or use the two completion links.

**Recommendation:** Remove the automatic redirect, or provide an announced countdown with a way to stop/extend it. Prefer leaving the user on the success screen until they choose a destination.

**WCAG:** 2.2.1 Timing Adjustable.

### R2-04 — P1: disclosure fixes contain nested interactive controls

- Each unit uses `div.accordion-header role="button" tabindex="0"` while containing Rename, Save, Cancel, Publish, and Delete controls (`instructor-units.js:188-212`). Interactive controls inside an element exposed as a button produce an invalid/confusing accessibility tree.
- Instructor home uses the same pattern: a `role="button"` section header contains “More information” buttons and, in one case, Download (`home.html:173-211`).

The event code tries to avoid accidental toggles, but event guards do not correct the semantics. Use a dedicated native disclosure button beside the other controls, with `aria-expanded` and `aria-controls`.

**WCAG:** 1.3.1 Info and Relationships, 2.1.1 Keyboard, 4.1.2 Name/Role/Value.

### R2-05 — P1: important mouse-only targets remain

- Per-topic rows on Instructor Home use `div.topic-header onclick="toggleTopic(this)"` with no role, tab stop, keyboard handler, or expanded state (`home.js:464-479`).
- Wrong-answer quiz materials are downloadable `div.material-item` nodes with only `onclick` (`quiz.js:420-440`). They cannot be reached or activated with a keyboard.

The click handler on Super Course history rows is less severe because each row also exposes a native Continue button; retain the native button as the primary path and avoid presenting the row itself as interactive unless it receives complete semantics.

**WCAG:** 2.1.1 Keyboard, 4.1.2 Name/Role/Value.

### R2-06 — P1: disclosure and icon controls have incomplete names/state

- Unit subsection buttons are announced as “down-pointing triangle, button.” They have no meaningful name, `aria-expanded`, or `aria-controls` (`instructor-units.js:216-240, 274-275`; state code only swaps glyphs).
- Dynamically generated add/remove/edit/delete/rename/save/cancel controls frequently use only `+`, `×`, `✎`, `✏️`, `✓`, `✕`, or `🗑️`. Visible symbols become the accessible name, so `title="Delete question"` does not reliably replace “times.” This occurs in instructor objectives/questions/units and onboarding equivalents.
- Notes Browse/Add cards are now real buttons, but visual `.active` state is not exposed with `aria-pressed` or a tabs pattern.
- Instructor Settings and TA Settings links are visually the current page but lack `aria-current="page"`.
- The mobile toggle still lacks `aria-controls` tying its expanded state to the controlled sidebar/navigation region.

**WCAG:** 1.3.1 Info and Relationships, 2.4.6 Headings and Labels, 4.1.2 Name/Role/Value.

### R2-07 — P1: quiz results and help-chat responses are silent

Quiz answer feedback is revealed in a plain `div` with no live-region role (`quiz.html:150-154`). Focus remains on the submitted/next control, so correctness and explanation may not be announced. The quiz help chat message container also lacks `role="log"`/live behavior (`quiz.html:164-170`), even though the main chats were fixed.

Additional dynamic-state gaps:

- Short-answer textarea relies on its placeholder for its name.
- The progress text says “Question 1 of N” while `aria-valuenow` is set to `0` for the first question (`quiz.js:180-188`).
- Downloadable review materials are mouse-only (R2-05).

**WCAG:** 1.3.1 Info and Relationships, 3.3.2 Labels or Instructions, 4.1.2 Name/Role/Value, 4.1.3 Status Messages.

### R2-08 — P1: login lacks a main landmark and form switching loses focus

The login page is the only HTML page with no `<main>` landmark or skip target. Browser testing also confirmed that activating “Create one” results in the registration view being visible while `document.activeElement` is `<body>`. The new “Create Account” h2 or first field is not focused or announced. The reverse transition has the same implementation.

**WCAG:** 1.3.1 Info and Relationships, 2.4.1 Bypass Blocks, 2.4.3 Focus Order.

### R2-09 — P1: current automated contrast failure

The full suite fails on Instructor Flagged Content's error path:

```text
selector: #empty-state > p
foreground: #ef4444
background: #ffffff
ratio: 3.76:1
required: 4.5:1
source: instructor/scripts/flagged.js:1337-1348
```

This is a real dynamic error state, not a scanner-only false positive.

**WCAG:** 1.4.3 Contrast (Minimum).

### R2-10 — P1: course-copy modal has unnamed dynamic checkboxes and silent busy state

The Settings transfer grid generates three checkboxes per unit inside empty labels (`settings.js:1838-1853`). Column headings are visual `<div>`s, not programmatic labels, so a user cannot tell whether a checkbox means documents, objectives, or questions for a given unit.

When copying starts, the confirmation content is replaced with “Creating…” but the loading area is not a status/live region. Escape is ignored while busy only because `closeTransferModal()` returns; the reason is not announced.

**WCAG:** 1.3.1 Info and Relationships, 3.3.2 Labels or Instructions, 4.1.2 Name/Role/Value, 4.1.3 Status Messages.

### R2-11 — P2: visible section titles are missing heading semantics

Student and instructor Super Course “Sources” titles are styled `<div class="super-course-pool-heading">`, not headings. They are useful navigation points in a long chat page and should participate in the outline. The topic-to-unit dialog also incorrectly starts at h3 rather than the specialist's required dialog h2.

### R2-12 — P2: automated test gate can report misleading green results

- Heading tests explicitly `fixme` `/student` and `/student/history`, even though their current markup appears corrected (`heading-hierarchy.a11y.spec.js:89-92`).
- Instructor question and Remove TA modal keyboard tests are always `fixme` because fixtures do not expose triggers (`modal-keyboard.a11y.spec.js:53-69`).
- No keyboard-contract tests cover agreement, idle timeout, chat limit, survey, onboarding duplicates, upload, learning objective, auto-link, regenerate, delete, calibration, downloads, topic assignment, transfer, document preview, or question review.
- `/qdrant-test` passed axe while the server logged `ENOENT ... public/qdrant-test.html`. The test asserts no response status or expected page identity before scanning (`shared.a11y.spec.js:17-20`).
- Axe uses only `wcag2a`/`wcag2aa` tags and blocks only critical/serious impacts (`axe-helper.js:5-8`). Moderate findings—including heading/order issues—remain warnings and are easy to miss. WCAG 2.2 tags and a deliberate moderate-issue ratchet are absent.
- Standard `npm run test:a11y` failed in this audit environment before discovery with the default Node runtime; the suite only ran after invoking Playwright with the workspace runtime. Document and enforce a supported Node version so the local gate is reproducible.

### R2-13 — Verify with the specialist: checks code and axe cannot certify

Run these per representative pattern, not just per URL, following the linked manual-testing article:

1. **VoiceOver + Safari on macOS** and, if possible, **NVDA + Chrome on Windows**: navigate landmarks/headings; operate forms; hear validation, chat replies, quiz feedback, idle warning, upload/download progress, survey, and completion states.
2. **Keyboard only:** first Tab exposes Skip link; activate it; traverse visual order; operate every mouse action; open each dialog; cycle forward/backward; Escape; confirm focus return.
3. **Focus appearance:** verify the global blue 3px indicator remains at least 3:1 against every light/dark/component background and is not clipped.
4. **Zoom/reflow:** 200% and 400% at 1280 CSS px; confirm no two-dimensional scrolling for ordinary content and no controls/text are lost.
5. **Text spacing:** apply WCAG spacing overrides and confirm no clipping/overlap.
6. **Forced colors/high contrast** and **reduced motion:** verify controls remain perceivable. Only Settings currently declares `prefers-reduced-motion`; the stylesheets contain many transitions/animations.
7. **Touch/mobile + keyboard:** mobile header expanded state, focus order, and target relationship.
8. **Reading/cognitive review:** ask whether agreement, mental-health, timeout, AI notice, and course-transfer copy is clear enough for the intended university audience.

## Recommended meeting agenda

1. Demonstrate the confirmed improvements table, especially skip link, heading outline, chat log, agreement heading focus, and the passing dashboard modal keyboard test.
2. Be candid that modal consistency is the largest remaining engineering risk; show one helper-backed dialog and one onboarding/chat-limit dialog that bypasses it.
3. Ask the specialist to validate the proposed onboarding focus behavior and whether native `<dialog>` is preferred over completing the custom helper.
4. Use the remaining time on a real screen-reader pass of chat, quiz feedback, idle timeout, and course upload—the primary flows with the highest user impact.
5. Agree on the manual regression matrix and which browser/screen-reader pairs become release requirements.
