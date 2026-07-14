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
  "events":         [ ...button clicks like "summarize"... ]
}
```

### `metadata` — the header

Tells you whose session this is and its scope. From the example:

| Field | Meaning |
|---|---|
| `exportDate` | When *you* clicked download (UTC) |
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
| `questionData` | Present on assessment questions: the options and which one was selected |
| `htmlContent` | The rich, formatted version of `content` (e.g. a score card) when one exists |
| `triggeredBy` | If the message came from a button, which one (e.g. `explain_button`, `summarize_button`) |

**`messageType` values you'll see:**

- `regular-chat` — an ordinary message from student or bot.
- `assessment-start` — the bot announcing the start of the pre-chat assessment.
- `practice-test-question` — a question the student was asked. Look in `questionData`
  for the options and the selected answer.
- `mode-result` — the result of the assessment, including the score summary and which
  mode the bot switched into. `modeData.determinedMode` gives the chosen mode.

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

- `sessionInfo` gives the session `startTime`, `endTime`, and a human-readable
  `duration` (e.g. `"3m 27s"`), plus a `sessionId`.
- `events` logs button actions during the session — for instance a `summarize_button`
  click that produced a chat summary.

---

## Reading across two exports (sessions)

A student's work is split into **sessions**. When the app hits a message limit or the
student starts fresh, it opens a new session and carries a **summary** of the previous
one into the next. You'll see this in a pair of files:

- The **first** session ends with a `summarize_button` event.
- The **next** session opens with a student message whose `isSummarySeed` field is
  `true`. This is **not** something the student typed — it's the auto-generated recap of
  the earlier session, injected so the bot keeps its context. If you see a long, polished
  "student" message that summarizes the whole prior conversation, that's the seed.

So when two files look like they belong together, order them by `sessionInfo.startTime`
and treat the `isSummarySeed` message as the bridge between them.

---

## Understanding the timing fields

**`elapsedTime`** is the number of **milliseconds between a message and the one before it**
in the conversation. It's always the difference between the two `timestamp` values, so it
matches the timestamps exactly (the "well hi" message shows `3639`, and its timestamp is
3.639 seconds after the bot message before it). The first message in a session is `0`,
since nothing comes before it.

**`elapsedTimeDerived`** does *not* mean the value is estimated or unreliable — both cases
are computed the same way, by subtracting timestamps. It only records *when* the number
was calculated:

- `false` — computed live, at the moment the message was sent.
- `true` — filled in later (for example during export) from the stored timestamps.

The one thing to keep in mind is **what the gap includes**. It's raw wall-clock time since
the previous message, so:

- a **bot** message's `elapsedTime` is roughly how long the bot took to respond, but
- a **student** message's `elapsedTime` includes however long they spent reading the bot's
  previous reply *and* typing their own.

So it's a reliable message-to-message gap, but it is **not** a clean measure of how long
the student was actively working. If you want precise timing for your own analysis, the
`timestamp` fields are exact UTC times and you can compute any interval you like from them.
(`displayTimestamp` — e.g. `"Just now"` — is only the friendly label shown in the app at
export time; ignore it for analysis.)

---

## Quick reference: is this the student or the bot?

This trips people up most, so to summarize:

- **`type: "user"`** → the student typed it. **Exception:** a `user` message with
  `isSummarySeed: true` is the auto-generated summary from a prior session, not the student.
- **`type: "bot"`** → BiocBot. **Exception:** if `sourceAttribution.source` is
  `"System"`, it's an automatic app notice, not the bot's own response.
- **`feedbackRating`** on a bot message is the *student's* rating of that reply.
