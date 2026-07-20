# A11y remediation prompts — round 2

These prompts replace the now-stale first-round list. Do not start them during the audit-only pass. Run in the order shown unless a task says it is independent.

## General rules (prepend to every implementation prompt)

```text
Rules for this task:
- Read audits.md at the repository root first. Only address the named round-two finding(s).
- Do not change unrelated behavior or visual design. Preserve existing classes when changing semantics.
- Prefer native HTML semantics. Do not add ARIA where a native element provides the behavior.
- Never add role="button" to a container that contains buttons, links, inputs, labels, selects, or textareas.
- For every dynamic control, verify its accessible name and state in the rendered accessibility tree, not only in source.
- Do not suppress axe rules or add test.skip/test.fixme to make the task green.
- Add or update a focused regression test for the behavior being fixed.
- Run the smallest relevant test first, then the full accessibility suite. Report passes, failures, and skips separately.
- Do not touch audits.md or mark a finding resolved until verification passes.
```

## Task 1 — Restore a trustworthy accessibility test gate (R2-12)

```text
Make the existing accessibility gate fail on missing/wrong pages and stop skipping corrected coverage.

1. In heading-hierarchy.a11y.spec.js, remove the fixme for /student and /student/history. Run both and fix the test setup only if necessary; do not weaken heading assertions.
2. In shared.a11y.spec.js, capture the navigation response for /qdrant-test and assert a successful response plus a page-specific landmark/heading before running axe. If the route is genuinely removed, remove it from the a11y route inventory instead of scanning an error page.
3. Seed a visible question trigger and removable TA so the two modal-keyboard fixmes can run. No unconditional skip/fixme may remain.
4. Add WCAG 2.2 A/AA tags supported by the installed axe version. Preserve WCAG 2.0/2.1 coverage.
5. Emit a machine-readable summary containing page, rule, impact, selector, and details for every violation, including moderate/minor warnings.
6. Document and enforce a Node version that can run npm run test:a11y directly in this repository.

Acceptance: test discovery has zero unconditional skips/fixmes; /qdrant-test cannot pass on a 404/ENOENT page; npm run test:a11y starts with the documented runtime.
```

## Task 2 — Establish one modal implementation contract (R2-01; prerequisite for Tasks 3–4)

```text
Decide and implement the shared modal foundation before wiring more dialogs.

Preferred option: native <dialog> opened with showModal(). Preserve the current overlay/card appearance with CSS. If the custom helper must remain, add equivalent background inertness and prove the behavior with tests.

Contract for every modal:
- dialog/alertdialog role and explicit accessible name from an h2;
- h2 has tabindex="-1" and receives focus on open unless a documented destructive/urgent exception is approved;
- Tab and Shift+Tab cannot enter background content;
- Escape closes and restores focus, except forced-choice/busy dialogs where Escape is prevented and the reason is available to AT;
- every close path restores the exact trigger;
- opening one modal while another closes cannot restore focus to a hidden element;
- background click behavior matches the Escape policy;
- no duplicate heading ids across pages or generated instances.

Add a reusable keyboard-contract test helper covering Enter activation, initial focus, forward/backward containment, Escape policy, and focus return. Do not rely on 20 Tabs alone; assert first/last boundaries in both directions.
```

## Task 3 — Wire all static/onboarding dialogs to the contract (R2-01)

```text
Using Task 2's contract, audit every open and close path for:
- instructor document page: question create/edit, learning-objective edit, auto-link, regenerate, upload, delete unit, calibration;
- instructor onboarding duplicates: question create/edit, learning-objective edit, auto-link, regenerate, upload;
- dashboard confirmation, idle timeout, agreement, topic review;
- downloads student details/progress, Remove TA, Settings course-copy review.

The onboarding versions currently live in onboarding-objectives-questions.js and onboarding-ai-generation.js and only toggle .show. They must not be assumed fixed because the non-onboarding versions call the helper.

Forced-choice policies:
- required agreement: Escape is intercepted;
- idle timeout: Escape is intercepted while the warning is active;
- download/course-copy busy state: provide an announced reason if it cannot close.

Add one real-trigger keyboard test per distinct implementation, including onboarding duplicates and focus return after async state changes.
```

## Task 4 — Fix dynamically generated dialogs (R2-01, R2-10)

```text
Apply the Task 2 contract to dynamic dialogs that page-level modal scans miss:
- student chat-limit info;
- student chat survey;
- instructor topic-to-unit assignment;
- document preview;
- extracted-question review;
- Settings course-copy review and its populated unit grid.

Specific requirements:
- topic-to-unit starts with h2, not h3;
- extracted-question review close button is named Close;
- chat survey star groups retain radio semantics and gain expected arrow-key radio behavior;
- course-copy unit checkboxes have unique names containing both unit and column purpose, e.g. “Unit 2: copy documents and chunks”;
- busy/loading text is a scoped status region and is not announced every second;
- generated dialogs are included in axe scans after their real builder/population path runs.
```

## Task 5 — Repair onboarding focus, skip targets, and timing (R2-02, R2-03)

```text
For instructor and TA onboarding:
1. Keep exactly one active #main target. When the visible step/completion screen changes, move id="main" and tabindex="-1" to that screen's h1 (or use another specialist-approved stable pattern).
2. After user-triggered Next/Back/substep changes, focus the new screen/substep heading. Do not steal focus during initial hydration unless resuming directly into a later step needs context announced.
3. Ensure every visible state begins with one h1 and retains sequential descendant headings.
4. Remove TA onboarding's unconditional five-second redirect. Leave the completion screen until the user chooses a destination, unless an accessible adjustable timer is deliberately implemented.
5. Give onboarding progress bars coherent value text and announce only meaningful step changes.

Tests: activate each step transition with keyboard; assert visible #main, focused heading, outline, Back behavior, and no timed navigation from TA completion.
```

## Task 6 — Replace nested/click-only disclosures with native controls (R2-04, R2-05, R2-06)

```text
Refactor disclosure triggers without changing appearance:
- unit accordion: replace div[role=button] with a dedicated native button that does not contain Rename/Publish/Delete controls;
- instructor Home section headers: use a dedicated button separate from info and Download buttons;
- instructor Home per-topic rows: make the heading's disclosure a native button;
- unit subsection triangle buttons: meaningful names, aria-expanded, aria-controls, and hidden decorative glyphs;
- quiz material downloads: use <button> for an action or <a download> for a resource URL.

Every disclosure must update aria-expanded from the actual content state, point to a unique controlled id, work with Enter/Space, and leave sibling controls independently reachable. Remove redundant click handlers from generic containers.

Tests must enumerate mouse actions on these patterns and prove an equivalent keyboard path for each.
```

## Task 7 — Finish control naming and selected/current state (R2-06)

```text
Find generated icon/symbol-only buttons across instructor, onboarding, student, and TA code. Add context-specific accessible names; hide decorative symbols from AT. Cover add/remove objective, add/remove/delete/edit question, rename/save/cancel/delete unit, remove approved topic, and any notification/modal close control missed by the existing grep.

Also:
- expose Notes Browse/Add selection as a proper tabs pattern or aria-pressed toggle buttons, including panel relationships and keyboard behavior;
- add aria-current="page" to Instructor Settings and TA Settings user-action links;
- give the mobile navigation region a stable id and connect the toggle with aria-controls.

Verification must inspect computed accessible names in Playwright. A non-empty name such as “×” or “pencil” is not an acceptable pass.
```

## Task 8 — Make quiz state and responses perceivable (R2-07)

```text
1. Give the short-answer textarea a persistent visible label (preferred) or an explicit accessible name.
2. Announce one concise answer-result message when feedback becomes visible; avoid placing the entire question card in aria-live.
3. Make quiz help chat a role="log" with additions announced, matching the main chat behavior. Keep typing status separate and polite.
4. Align progress semantics: Question 1 of N must not expose aria-valuenow=0. Choose a 1..N range or explicit aria-valuetext and keep it consistent through completion/filter changes.
5. After Next Question, place focus at the new question heading/text using a deliberate programmatic-focus target.
6. Convert review material items as described in Task 6.

Add tests for correct, incorrect, short-answer, help-chat response, next-question focus, and completion states.
```

## Task 9 — Fix login landmarks and view-transition focus (R2-08)

```text
Wrap the login card's primary content in <main>. Give Sign In and Create Account stable focusable headings. When Create one / Sign in switches views, focus the newly visible heading (or first invalid field only after a validation failure). Preserve role="alert" for submission messages.

Because the page has very few repeated blocks, decide with the specialist whether a skip link adds value; if added, it must be the first focusable element and target the active view, never a hidden form.

Add a keyboard test that activates each switch link and asserts the visible heading is focused and the hidden form is absent from the accessibility tree/tab order.
```

## Task 10 — Fix live contrast failure and ratchet contrast coverage (R2-09)

```text
Change only the Instructor Flagged Content dynamic error color/style needed to reach at least 4.5:1 for normal text on its actual background. Do not darken unrelated branding colors.

Reproduce the real error state and assert the exact selector is scanned. Then run the full suite and record any remaining contrast findings, including focus indicators and populated/disabled/error states that static scans miss.
```

## Task 11 — Complete structure and manual regression coverage (R2-11, R2-13; do last)

```text
1. Change the student/instructor Super Course “Sources” titles to h2 while preserving styling.
2. Extend heading tests to each visible onboarding step/completion state and every open modal; dialogs must start at h2.
3. Create a documented representative-pattern manual matrix for mouse, keyboard, screen reader, contrast, 200%/400% zoom, text spacing, forced colors, reduced motion, and mobile+keyboard.
4. Record browser/screen-reader/version, exact route/state, steps, expected result, actual result, WCAG SC, severity, and screenshot/recording link.
5. Do not mark VoiceOver/NVDA, focus contrast, reflow, or announcement checks passed based on axe or DOM inspection alone.

Completion requires zero unexplained accessibility test skips, a green automated suite, and a signed-off manual pass for the primary student, instructor, and TA flows.
```
