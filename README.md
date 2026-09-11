# 🚀 RSROLEPLAY Engine

A lightning-fast, fully serverless AI roleplay platform powered by **Cloudflare Workers**, **Cloudflare D1** and **Durable Objects**. Build your own private roleplay hub — with characters that each have their own look, replies that survive a closed tab, and an interface you can reshape completely — at zero hosting cost. Or just use it as your everyday AI chat client.

**Built by [@redsus.vn](https://miku.us.kg) |  Follow my tiktok for more info [https://www.tiktok.com/@redsusvn](https://www.tiktok.com/@redsusvn)**

### 🎬 [Watch the showcase video](https://storecloud.eu.org/0911.mp4)

<video src="https://storecloud.eu.org/0911.mp4" controls muted playsinline width="100%"></video>

---

## ✨ Features

### Replies you can rely on
- **⚡ 100% Serverless:** Runs entirely on Cloudflare's Edge (Workers + D1 + Durable Objects). No VPS, no backend. Everything fits in the **Free** plan.
- **🛡️ Replies that can't get lost:** Your message is saved *before* the AI is called, and the reply is written to the database while it streams — every couple of seconds at first, then further apart (never more than 25 s), so even a four-minute reply stays inside the Free plan's database limit. Close the tab, lose signal, switch apps — when you come back the reply is there (or still growing, and the page follows it live).
- **🔁 Auto-resume:** If the AI provider drops the connection mid-reply, the server reconnects and asks the model to continue from exactly where it stopped, stitching the halves together.
- **🧠 Thinking models:** Native support for reasoning models (DeepSeek R1, Qwen3, Gemma/Gemini `<thought>` output) with an expandable **Thought Process** block.
- **🔌 Multi-provider:** Groq, OpenRouter, Mistral, Cloudflare AI, Gemini, or any OpenAI-compatible endpoint. **Browse** lists a provider's models so you don't have to type IDs, and **Test** checks an endpoint before you rely on it.
- **🎛️ Generation presets:** Default, Creative, Precise — or Custom, with temperature, top-p, top-k and presence / frequency / repetition penalties.

### Roleplay
- **🎭 Characters:** Each persona has a portrait (image link, inline image, emoji or initials), a description, a system prompt, a greeting, and a *user persona* — who **you** are in that story.
- **🔀 Swipe variants:** Regenerate a reply and swipe between the versions, like a native app.
- **📌 Sketchboard:** Pin facts, rules and promises to a chat so the AI never forgets them.
- **📚 Auto-summarization:** Old messages are summarized in the background to keep long stories inside the model's context window.
- **🔄 Character.AI import / TXT export:** Drop in a `.txt` history exported from Character.AI, or download any chat as `{user}` / `{bot}` tagged text.

### Make it yours
- **🧩 10 layouts** — not recolours, different interfaces: Studio, Rail, Trio, Zen, Deck, Console, Ledger, Split, Canvas, Tiles.
- **🎨 6 palettes** (Graphite, Aurora, Vellum, Clay, Void, Sherbet) × any accent colour. The whole palette is rebuilt around the colour you pick, for light and dark mode.
- **💬 240 bubble designs** in 16 families — classics, gradients, neumorphism, retro terminals, animated "living" effects, emoji patterns, scenery, ears and paws… Give the AI and yourself different designs, recolour any of them, set how see-through they are, and let **Readable text** darken the words automatically when a design is too bright behind them.
- **🫧 Liquid glass:** Real refraction — the sidebar, header, bubbles and buttons bend the wallpaper behind them — with a frost slider. Switches itself off when your system asks for reduced transparency.
- **🖼️ Wallpapers:** An image or a video link (`.mp4`, `.webm`, `.mov` play muted and looping), or a file straight from your device (up to 120 MB, kept on that device). Dim, blur and show-through controls.
- **🖱️ Custom cursor:** Built-in cursors, a cursor page link (e.g. rw-designer.com), a direct `.png` / `.gif` / `.cur` link, or your own upload — with an adjustable click point and size.
- **👥 A look per character:** Every appearance setting can apply **everywhere**, to **one persona**, or to **one chat**. Open a character's chat and the bubbles, accent colour and wallpaper change with them.
- **☁️ Your look follows your account:** Appearance is stored in the database, so a second device picks it up when you sign in. Only a wallpaper picked from a device's own files stays on that device.
- **🗂️ Docked panels:** In the Rail, Trio and Split layouts (on screens 1024 px and wider), panels like Personas, API Endpoints and Memory open in the side column instead of a popup. **Current Chat** folds the column away and gives the conversation the full width.

### Private and secure
- **🔐 Two-factor sign-in:** Any authenticator app (Google Authenticator, Aegis, 1Password…) plus one-time recovery codes. See the lockout rules below — they are strict on purpose.
- **🧱 Nothing of yours before sign-in:** Every endpoint that holds data needs a signed-in session. Signed out, all anyone gets is the login form — and wrong passwords lock their IP out for a while.
- **🧼 Sanitized output:** Everything the AI writes is cleaned before it is shown, and every response carries a Content Security Policy and hardened security headers.

### On your phone
- **📲 Installable:** Add it to your home screen on Android or iPhone and it opens like an app, with its own icon. There is deliberately no service worker, so an installed copy never keeps an offline copy of your chats.
- **📱 Built for touch:** 44 px tap targets, dialogs that always fit the visible screen (address bar and all), and glass effects taken off the things that scroll, so long chats stay smooth.

---

## 🛠️ Installation Guide

There are two ways to install. **Method A is the one to use** — it is the only way to get the Durable Object that makes long replies reliable on the Free plan. Method B needs nothing installed but is limited (see the note at the end of it).

### Prerequisites
- A [Cloudflare](https://dash.cloudflare.com) account (Free tier is perfect).
- An API Key from an AI provider (e.g., [GroqCloud](https://console.groq.com/home)).
- For Method A: [Node.js](https://nodejs.org) (LTS) installed on your computer.

---

### Method A — Recommended: deploy with `wrangler` (≈10 minutes)

> **Why this matters:** a plain Worker on the Free plan gets only **10 ms of CPU per request**, which a long streamed reply exceeds — Cloudflare then kills the request mid-reply. The engine therefore runs each reply inside a **Durable Object**, which gets **30 s of CPU** and keeps running after you close the page. A Durable Object can only be created by a *migration*, which the dashboard cannot do — `wrangler` can.

> **💡 Shortcut — the setup helper.** Instead of Steps 3–5 below, you can run
> ```bash
> node setup/server.mjs
> ```
> and open **http://127.0.0.1:8788**. It walks you through creating an API token (it tells you exactly which permissions to tick: *Workers Scripts · Edit*, *D1 · Edit*, and optionally *Account Settings · Read*), picking your account, naming the Worker and creating the database, then writes a ready-to-use `wrangler.toml` for you. You still run `npx wrangler deploy` yourself (Step 6). It is one file with no dependencies, it only listens on your own machine, and the token never touches your disk. *(Its interface is in Vietnamese.)*

#### Step 1: Get the files
Download this repository (**Code → Download ZIP**) and unzip it. You need two files in the same folder: `worker.js` and `wrangler.toml`.

#### Step 2: Open a terminal in that folder
Windows: open the folder in Explorer, click the address bar, type `powershell`, press Enter.
macOS/Linux: open Terminal and `cd` into the folder.

#### Step 3: Log in to Cloudflare
```bash
npx wrangler login
```
The first run asks to install wrangler — answer `y`. A Cloudflare page opens in your browser: click **Allow**.

#### Step 4: Create the database
```bash
npx wrangler d1 create rsroleplay-db
```
The output contains a `database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` line. Copy that UUID.

#### Step 5: Edit `wrangler.toml`
Open `wrangler.toml` in any text editor and set these three lines:
```toml
name = "myownchatplatform"          # the name your Worker (and its URL) will have
database_name = "rsroleplay-db"     # the name you used in Step 4
database_id = "PASTE-THE-UUID-FROM-STEP-4"
```
Leave the rest of the file as it is — it already declares the `DB` binding, the `STREAMER` Durable Object and its migration, the daily cleanup cron, and Smart Placement.

#### Step 6: Deploy
```bash
npx wrangler deploy
```
When it finishes you should see both bindings listed:
```
env.STREAMER (ChatStreamer)      Durable Object
env.DB (rsroleplay-db)           D1 Database
```
and your URL: `https://myownchatplatform.<your-subdomain>.workers.dev`.

Continue with **First-time setup** below.

---

### Method B — Dashboard only (no terminal, limited)

#### Step 1: Create a Cloudflare Worker
1. Log in to your Cloudflare Dashboard.
2. On the left sidebar, navigate to **Workers & Pages**.
3. Click **Create** -> **Create Worker**.
4. Name your worker (e.g., `myownchatplatform`) and click **Deploy**.

#### Step 2: Paste the Source Code
1. Once deployed, click **Edit Code** on your new Worker.
2. Delete all the default code in `worker.js`.
3. Copy the entire content of `worker.js` from this repository and paste it in.
4. Click **Deploy** in the top right corner.

#### Step 3: Create the D1 Database
1. Go back to the main Cloudflare Dashboard sidebar.
2. Expand **Storage & databases** and click **D1 SQL database**.
3. Click **Create Database**.
4. Give it a memorable name (e.g., `rsroleplay-db`) and click **Create**.

#### Step 4: Bind the Database (Crucial Step ⚠️)
1. Go back to **Workers & Pages** and click on your Worker.
2. Go to the **Settings** tab, then click **Bindings**.
3. Click **Add Binding** and select **D1 database**.
4. **Variable name:** Type exactly `DB` *(Must be fully capitalized!)*
5. **D1 database:** Select the database you created in Step 3.
6. Click **Deploy / Save**.

> **Limitation of Method B:** there is no `STREAMER` Durable Object, so replies are generated inside the Worker's 10 ms CPU budget. Short and medium replies work; very long ones can be cut off by Cloudflare ("Worker exceeded CPU time limit" in the logs). Whatever arrived is still saved and you can press **Retry**, but for full reliability switch to Method A at any time: install Node.js, put your existing Worker name and database name/ID into `wrangler.toml` (the ID is on the D1 database page), then run `npx wrangler login` and `npx wrangler deploy`. Your chats are kept — it is the same database.

---

### First-time setup & Admin account
1. Open your Worker's `.workers.dev` URL in your browser.
2. You will be greeted by the First Time Setup screen.
3. Enter your desired Admin Username and Password.
   > *Note: You can only create ONE account for this private instance. Keep your credentials safe!*

### Connect your AI (API Endpoints)
1. Log in to your RSROLEPLAY instance.
2. Click **API Endpoints** in the left sidebar (or the **+** next to its close button).
3. Click **+ Add Endpoint**.
4. Select your provider (e.g., `Groq`), paste your API Key, then enter the Model ID — or press **Browse** to pick it from the provider's list (e.g., `llama-3.3-70b-versatile`).
5. Check the **Set as Primary** box and click **Save Key**. Press **Test** on the endpoint to make sure it answers.

### AI model names
- Chat model name: `google/gemma-4-26b-a4b-it`
- Summarize model name: `llama-3.3-70b-versatile`

### Recommended models
- OpenRouter: `nvidia/nemotron-3-super-120b-a12b:free`
- Gemini: `gemma-4-26b-a4b-it` and `gemma-4-31b-it`, both work well.

🎉 **You're done!** You can now go to "Current Chat" and start talking to your AI.

---

## 🔐 Two-factor sign-in

Turn it on in **Account Settings → Two-factor authentication**: scan the QR code with an authenticator app, confirm a code, and **save the recovery codes it shows you** — each one works once, and they are your only way in if you lose the phone.

The lockout is deliberately strict:

| Wrong codes | What happens |
|---|---|
| 3 | wait **10 minutes** |
| 1 more | wait **30 minutes** |
| 1 more | wait **1 hour** |
| 1 more | **the account is locked for good** — its name and password are replaced with random characters |

The login page never says which of these you are in — a wrong code only ever answers *"Please try again."* So don't guess: use a recovery code instead.

If it ever happens to you, your chats and keys are untouched. Clear the locked account from the command line and set up again — and do it in one go, because the site offers first-time setup to whoever opens it first:
```bash
npx wrangler d1 execute rsroleplay-db --remote --command "DELETE FROM users; DELETE FROM user_sessions"
```

---

## 🎨 Making it yours

Everything lives under **Appearance** in the sidebar:

- **Theme** — pick one of the 10 layouts.
- **Style** — extra options for the layout you picked.
- **Colour** — the palette and any accent colour; everything is rebuilt around it. (Dark or light: **Toggle Theme** in the sidebar.)
- **Bubble** — browse the 240 designs, for the AI's side, yours, or both.
- **Bubble setup** — recolour the chosen design, set its opacity, change the emoji of an emoji-pattern design, and toggle *Readable text*, *Outline behind text* and the design's own font.
- **More** — liquid glass, wallpaper, cursor.

**Applies to** at the top of the panel decides where a change lands: **Everywhere**, **this persona** or **this chat**. A persona-level look is how each character gets their own bubbles, colour and wallpaper — switch chats and the whole interface changes with them.

---

## 🎞️ Demo content

Want to see it full of life before you have written a single story? `demo/seed.sql` adds eight original characters with portraits, their own bubble designs and wallpapers, and a finished conversation each — with swipe variants, thought-process blocks, sketchboard pins and memory summaries.

```bash
npx wrangler d1 execute rsroleplay-db --remote --file demo/seed.sql
```

Use `--local` instead of `--remote` to try it on `wrangler dev` first. To take it all out again — and only it — run the same command with `demo/unseed.sql`. Your own personas, chats and keys are never touched: every demo row has an id starting with `demo-`. The one thing it adds to your settings is a look for each demo character, and `unseed.sql` takes those out too.

*The portraits and wallpapers are from [Pixabay](https://pixabay.com) (Pixabay Content License). The portraits are embedded in the database; the wallpapers load from Pixabay's servers.*

---

## ⬆️ Updating an existing installation

Your chats, personas, keys and appearance live in D1 and are kept across updates. The database schema upgrades itself on the first request after an update.

- **Installed with Method A:** download the new `worker.js` (and `wrangler.toml` if it changed) into your folder, keep your three edited lines, run `npx wrangler deploy`.
- **Installed with Method B:** open the Worker → **Edit Code**, replace everything with the new `worker.js`, click **Deploy**. Bindings are kept. To also get the Durable Object, follow the switch-over note under Method B.

After updating, just reload the app — the new version is picked up automatically.

---

## 💡 Pro Tips

### Importing from Character.AI
1. Use a C.AI history exporter extension to get a `.txt` file of your chat.
2. In RSROLEPLAY Engine, click **Data Sync**.
3. Drag and drop your `.txt` file into the "Import Session" box.
4. **Tip:** Use Google Gemini to summarize your C.AI history into a structured "Persona" and "System Prompt" so your bot acts exactly like it used to!

### Chat Summarization Prompt

```
### ROLE: Professional Narrative Analyst and Roleplay Architect
### TASK: Analyze the provided chat history to create a comprehensive "Story Bible." 
Your goal is to extract every essential data point, nuance, and plot thread to ensure the conversation can be resumed with 100% consistency. You must condense the history into a structured, high-density briefing for a future AI model.
---
### OUTPUT FORMAT
Follow this structure EXACTLY. Use the headers provided.
{PROMPT AND INFORMATION}
[BOT CHARACTER INFO]
* Name: 
* Personality & Core Traits: (A deep dive into their psyche, temperament, and hidden layers)
* Backstory/Lore: (History and secrets revealed during the chat)
* Physical Description: (Appearance, unique features, current attire)
[USER INFO]
* Name/Role: 
* Character Traits: 
* Current Motivation: (What is the user character currently trying to achieve?)
[CONVERSATION & NARRATIVE STYLE]
* Chatting Style: (e.g., Casual, formal, average length of responses, use of OOC)
* Bot Talking Style: (Vocabulary choices, accents, stutters, specific sentence structures, or catchphrases)
* Narrative Style: (Detailed description of the "Narrator" voice—e.g., poetic, gritty, third-person limited, first-person, focusing on internal monologue vs. external action)
{CHAT HISTORY}
[THE CHRONOLOGICAL TIMELINE]
Provide a detailed, bulleted summary of the story from the first message to the current moment:
* Major Plot Points: (Key events that drove the story forward)
* Emotional Milestones: (Shifts in the relationship dynamics, e.g., trust built, betrayal, romance)
* Key Revelations: (Facts or lore uncovered during the roleplay)
* Current Location/Context: (Exactly where the characters are, the time of day, and the immediate situation)
{SPECIFIC REQUIREMENT FOR CHAT}
[CONTINUATION DIRECTIVES]
* Storytelling Quality: (Analyze what made the history successful and instruct the AI on how to maintain it—e.g., "prioritize sensory details," "maintain slow-burn tension," or "focus on psychological realism")
* The "Vibe" to Maintain: (The specific atmosphere—e.g., Noir, Whimsical, Gothic Horror, High-Fantasy)
* Specific Constraints: (Operational rules based on the history—e.g., "Never speak for the user," "Always put internal thoughts in italics," "Keep responses under 3 paragraphs")
* Immediate Next Goal: (The specific focus for the very next response to maintain the current momentum)
---
### INPUT DATA: CHAT HISTORY BEGINS BELOW
[PASTE YOUR CHAT HISTORY HERE]
```

---

### Memory Optimization
If your bot starts acting forgetful, go to **Memory Rules**. Ensure the `Messages to Summarize` threshold is properly set based on your AI model's context window.

### Give each character a face
A persona's **Avatar** field takes an image link, an inline image (`data:image/png`, `jpeg`, `webp` or `gif`), an emoji, or two letters. Inline images travel with the character and never break because a host went down.

---

## ❓ Troubleshooting

- **"D1 database binding 'DB' not found"** — the `DB` binding is missing. Method B: redo Step 4. Method A: check `database_name` / `database_id` in `wrangler.toml` and deploy again (wrangler replaces the bindings with what is in that file).
- **Long replies stop partway / "Worker exceeded CPU time limit" in Observability** — you are running without the Durable Object. Switch to Method A.
- **A reply says "No reply was generated — your message was saved"** — the AI provider failed. Your message is kept; press **Retry**. Check the endpoint in **API Endpoints** with its **Test** button.
- **Replies appear all at once instead of streaming** — an ad blocker or privacy extension is holding back the live stream until it finishes. Add your Worker's address to its allow-list.
- **My look didn't follow me to another device** — it is pulled when you sign in, so reload once on the other device. A wallpaper picked from a device's own files is the one thing that stays on that device.
- **An avatar shows two letters instead of the picture** — the link must start with `http` or be an inline `png` / `jpeg` / `webp` / `gif` image. SVG is not accepted.
- **Locked out by two-factor** — wait out the timer in the table above, or use a recovery code. After the final wrong code the account is locked for good, so don't guess — the fix is in the Two-factor section above.
- **Where is the Durable Object?** — Dashboard → **Workers & Pages → Durable Objects** should list `ChatStreamer` after a Method A deploy, and the Worker's **Bindings** tab should show `STREAMER`.
