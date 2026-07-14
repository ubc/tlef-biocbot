# Interpreting the JSON Chat Export

When you download a student's chat from the **Downloads** page, you get two formats of the
same conversation:

- **TXT** — a plain, readable transcript. It's self-explanatory: each message is a labeled
  `STUDENT` / `BIOCBOT` block with a timestamp, HTML stripped out. If you just want to read
  what was said, open this and you won't need this guide.
- **JSON** — the full structured record, with every field the app tracks. Open this to
  analyze the data, filter it in a spreadsheet or script, or understand *why* the bot
  behaved a certain way.

This guide explains the **JSON** format, using a real exported session as the example.

---

## The shape of the file

The JSON is one object with a few top-level sections. Here's the whole shape:

```
{
  "metadata":       { ...who, which course, which unit, how many messages... },
  "messages":       [ ...every message, in order... ],
  "practiceTests":  { ...the assessment questions and answers... },
  "studentAnswers": { ...what the student selected... },
  "sessionInfo":    { ...start/end time and duration... },
  "events":         [ ...session-level button actions like "summarize"... ]
}
```

`events` is optional and may be absent when the session has no recorded
session-level actions.

### `metadata` — the header

Tells you whose session this is and its scope. From the example:

| Field | Meaning |
|---|---|
| `exportDate` | When this stored session record was last updated or assembled (UTC). In a combined download, the outer export object has a separate download-time `exportDate` |
| `courseName` / `courseId` | The course |
| `studentName` / `studentId` | The learner |
| `unitName` | Which unit they were working in (e.g. `Unit 1`) |
| `currentMode` | The bot's teaching mode at export time — `tutor` or `protege` |
| `totalMessages` | How many messages are in this file |

### `messages` — the conversation

An array of message objects, oldest first. The two fields you'll always look at are
`type` (`user` = student, `bot` = BiocBot) and `content` (the text). Everything else is
context. The fields worth knowing:

| Field | What it tells you |
|---|---|
| `type` | `user` (student) or `bot` (BiocBot) |
| `content` | The message text |
| `timestamp` | When it was sent (UTC) |
| `messageType` | The *kind* of message — see the list below |
| `feedbackRating` | The thumbs the **student** gave the bot's reply: `up`, `down`, or `null` (no rating) |
| `sourceAttribution` | Which course materials the bot drew on for this reply (unit, document type). `null` for student messages |
| `hasFlagButton` | Whether this message could be flagged for review |
| `isHtml` | Whether `content` contains HTML markup |
| `elapsedTime` | Milliseconds since the previous message — see [the timing section](#understanding-the-timing-fields) |
| `elapsedTimeDerived` | Whether `elapsedTime` had to be reconstructed later from stored timestamps |
| `questionData` | Present on assessment questions: the options and which one was selected |
| `htmlContent` | The rich, formatted version of `content` (e.g. a score card) when one exists |
| `triggeredBy` | If the message came from a button, which one (e.g. `explain_button`, `summarize_button`) |
| `actionStatus` | Whether the button-triggered action succeeded; currently logged successful actions use `success` |
| `sourceMessageId` | On an Explain response, the ID of the bot message the student asked BiocBot to explain |
| `isSummarySeed` | `true` when this user-shaped message is an automatically generated recap carried into a new session |

**`messageType` values you'll see:**

- `regular-chat` — an ordinary message from student or bot.
- `assessment-start` — the bot announcing the start of the pre-chat assessment.
- `practice-test-question` — a question the student was asked. Look in `questionData`
  for the options and the selected answer.
- `mode-result` — the result of the assessment, including the score summary and which
  mode the bot switched into. `modeData.determinedMode` gives the chosen mode.
- `mode-toggle-result` — a notice recording a teaching-mode change made after the
  assessment.
- `unit-selection` — the one-time welcome/unit-selection message in a genuinely new
  session. A session created by Summarize starts with its summary seed instead and does
  not add this welcome message.

**A note on system notices.** Messages like *"You've reached 25 messages…"* or
*"…after 15 messages, the quality of the responses might be degraded"* appear as `bot`
messages with `sourceAttribution.source` set to `"System"`. These are automatic app
notices, **not** something the bot chose to say.

### `practiceTests` and `studentAnswers` — the assessment

These record the short quiz the student took before chatting. `practiceTests.questions`
lists each question with its `correctAnswer`, the student's `studentAnswer`, and an
`isCorrect` flag. `studentAnswers` is the raw record of what they selected. In the
example, the student answered `False` to a True/False question whose correct answer was
`True`, so `isCorrect` is `false` and the score was `0/1`.

### `sessionInfo` and `events`

- `sessionInfo.startTime` is the earliest valid message timestamp in the session.
- `sessionInfo.endTime` is the session's last recorded activity time. A successful
  Summarize action updates the old session's end time to the Summarize event timestamp.
- `sessionInfo.duration` is the human-readable conversation duration (e.g. `"3m 27s"`).
  It measures from the **first user message** through the **last real bot response**. It
  excludes setup time before the first user message, such as a welcome or assessment,
  and does not extend to a later system notice or Summarize click. The app adds the
  relevant `elapsedTime` intervals when they are complete and falls back to the two
  boundary timestamps for legacy sessions that do not have complete elapsed timing.
- `sessionInfo.sessionId` identifies the session.
- `events` logs session-level actions that do not need a synthetic transcript message.
  A successful Summarize event has `type: "button_action"`,
  `triggeredBy: "summarize_button"`, `actionStatus: "success"`, and its own timestamp.

Explain is recorded differently because it produces a visible bot response. The response
message itself has `triggeredBy: "explain_button"`, `actionStatus: "success"`, and a
`sourceMessageId` linking it to the original bot message.

---

## Reading across two exports (sessions)

A student's work is split into **sessions**. When the app hits a message limit or the
student starts fresh, it opens a new session and carries a **summary** of the previous
one into the next. You'll see this in a pair of files:

- The **first** session ends with a `summarize_button` event.
- The **next** session opens with a student message whose `isSummarySeed` field is
  `true`, `triggeredBy` is `summarize_button`, and `actionStatus` is `success`. This is
  **not** something the student typed — it's the auto-generated recap of the earlier
  session, injected so the bot keeps its context. If you see a long, polished "student"
  message that summarizes the whole prior conversation, that's the seed. It is normally
  the first message in the new session; a separate welcome message is not added.

So when two files look like they belong together, order them by `sessionInfo.startTime`
and treat the `isSummarySeed` message as the bridge between them.

---

## Understanding the timing fields

**`elapsedTime`** is the number of **milliseconds between a message and the one before it**
in the conversation. The first message in a session is `0`, since nothing comes before
it. This value is stored on the message and is preserved when a chat is reopened from
history or restored after a reload; rendering an older chat does not replace its timing
with the reload time.

**`elapsedTimeDerived`** records how that interval was obtained:

- `false` — captured while the message was created and then preserved independently on
  subsequent reloads and exports.
- `true` — the message came from an older record without captured elapsed timing, so the
  interval was reconstructed later from the stored timestamps. Once reconstructed, it is
  also preserved rather than recalculated on each reload.

Derived values are still usable and are intentionally included in `sessionInfo.duration`.
The flag provides provenance: if you are auditing legacy data whose historical timestamps
may themselves be questionable, you can distinguish reconstructed intervals from timing
captured by the newer format.

The one thing to keep in mind is **what the gap includes**. It's raw wall-clock time since
the previous message, so:

- a **bot** message's `elapsedTime` is roughly how long the bot took to respond, but
- a **student** message's `elapsedTime` includes however long they spent reading the bot's
  previous reply *and* typing their own.

So it is a message-to-message wall-clock gap, but it is **not** a clean measure of how long
the student was actively working. For newer records, prefer the persisted `elapsedTime`
values when analyzing consecutive gaps; use UTC `timestamp` values when you need absolute
clock times or custom boundaries. For legacy records, check `elapsedTimeDerived` so you
know whether a gap was reconstructed from those timestamps. `displayTimestamp` (for
example, `"Just now"`) is only the friendly label shown in the app; ignore it for analysis.

---

## Quick reference: is this the student or the bot?

This trips people up most, so to summarize:

- **`type: "user"`** → the student typed it. **Exception:** a `user` message with
  `isSummarySeed: true` is the auto-generated summary from a prior session, not the student.
- **`type: "bot"`** → BiocBot. **Exception:** if `sourceAttribution.source` is
  `"System"`, it's an automatic app notice, not the bot's own response.
- **`feedbackRating`** on a bot message is the *student's* rating of that reply.
