# Screen reader tests

The checks in `tests/a11y` read the accessibility tree that Chromium computes.
The tests here listen to a real screen reader instead. Playwright opens the
page, [Guidepup](https://github.com/guidepup/guidepup) starts VoiceOver and
records what it says, and each test asserts on the spoken phrases.

They run VoiceOver with Playwright's WebKit browser, the engine Safari uses.
VoiceOver users mostly use Safari. A `voiceover-chromium` project exists as a
fallback, but VoiceOver with Chrome is the least used pairing.

While they run, the tests take over the Mac. VoiceOver speaks, and the tests
send real key presses to the frontmost window. Do not type or click until they
finish (about 3 to 5 minutes).

## One-time setup (macOS, by hand)

These change macOS settings, so you make them yourself:

1. In the macOS Terminal app, run:

   ```sh
   npx @guidepup/setup@0.29.3 setup --macos-ignore-tcc-db
   ```

   This turns off VoiceOver's welcome screen and dictation auto-enable, then
   opens VoiceOver Utility. In its **General** tab, tick **Allow VoiceOver to
   be controlled with AppleScript**. On macOS 26 with System Integrity
   Protection on, that tick is the only way to turn this on. Keep System
   Integrity Protection on. `--macos-ignore-tcc-db` stops the tool from writing
   the macOS permissions database. If it fails on Node 22 its error message can
   be hidden (guidepup/setup issue 77).
2. In System Settings → Privacy & Security → Accessibility, add **Terminal** and
   turn it on.
3. In System Settings → Privacy & Security → Full Disk Access, add **Terminal**
   and turn it on, then quit and reopen Terminal. While the tests run, Guidepup
   swaps in its own VoiceOver settings by linking files into VoiceOver's
   settings folder (`~/Library/Group Containers/group.com.apple.VoiceOver`).
   macOS 26 blocks that otherwise, and every test fails with "VoiceOver cannot
   be started", caused by `EPERM ... symlink`. Guidepup's own CI setup grants
   the same access. This lets anything run in Terminal read all your files, so
   turn it off again when you are not running these tests.
4. On the first run, macOS asks whether Terminal may control VoiceOver and
   System Events. Allow both. If it never asks and the tests fail with
   `Not authorized to send Apple events to VoiceOver. (-1743)`, turn both on in
   System Settings → Privacy & Security → Automation → Terminal, or run
   `tccutil reset AppleEvents com.apple.Terminal` so macOS asks again.

Run everything from one Terminal window, one run at a time. Two runs at once,
or a run from another app's terminal (which needs its own permissions), fails
with errors that look like setup problems.

Run the tests from the Terminal app so these permissions go to Terminal only.

## Run

```sh
npm run test:screen-reader
```

A run takes about 10 minutes. The server starts on port 8052 so the nodemon
dev server on 8050 is not restarted by the logs this writes. Each test saves
what VoiceOver said, and the result of each check, to
`a11y-results/screen-reader/<project>/<test>.json`, and attaches it to the HTML
report in `playwright-report-screen-reader/`.

## What is covered

The Course Upload page, against the findings in issue 724. 56 of its 64
findings can be checked by listening to VoiceOver:

| Checks | Findings |
|---|---|
| Names, roles and states, read out as you Tab: each copy of a repeated control names its unit, card or file, and no hidden icon is read | 1, 2, 3, 4, 7, 12, 18, 19, 20, 21, 23, 24, 26, 28, 32–36, 41–47, 53–55, 60–64 |
| Headings and lists: the level VoiceOver gives each heading, and "list, N items" on entering a list | 5, 13, 22, 30, 31, 51, 52, 57, 58, 59 |
| Status messages: what is read when a message appears | 15, 48 |
| Focus after an action: what VoiceOver reads next, and that the Dismiss control in a message can be reached and stays | 14, 16, 17, 37–40, 49, 50, 56 |

The other 8 (6, 8, 9, 10, 11, 25, 27 and 29) are contrast, target size and
visible-label findings, which a screen reader cannot perceive. They are checked
in Chromium by `tests/a11y/issue-724-course-upload.a11y.spec.js`. Both specs
build the page with `tests/a11y/helpers/course-upload-fixture.js`.

The tests are grouped by part of the page, because each one restarts VoiceOver,
and each test's title lists the findings it covers. Checks are soft, so a test
reports every finding it covers, not only the first that fails.

One more test checks that the heading key skips the content of a collapsed
unit. It is not one of the 724 findings, and it fails until that is fixed.

Still a human check: JAWS (the most used screen reader, which Guidepup cannot
drive), VoiceOver on iPhone, and whether the speech makes sense.
