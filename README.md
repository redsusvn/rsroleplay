# 🚀 RSROLEPLAY Engine

A lightning-fast, fully serverless AI chat platform powered by **Cloudflare Workers**, **Cloudflare D1** and **Durable Objects**. Build your own private, customizable AI roleplay hub with zero hosting costs, or use it as your AI chat client for daily usage.

**Built by [@redsus.vn](https://miku.us.kg) |  Follow my tiktok for more info [https://www.tiktok.com/@redsusvn](https://www.tiktok.com/@redsusvn)**

---

## ✨ Features

- **⚡ 100% Serverless:** Runs entirely on Cloudflare's Edge (Workers + D1 + Durable Objects). No VPS or backend required. Everything fits in the **Free** plan.
- **🛡️ Replies that can't get lost:** Your message is saved *before* the AI is called, and the reply is written to the database every 2 seconds while it streams. Close the tab, lose signal, switch apps — when you come back the reply is there (or still growing, and the page follows it live).
- **🔁 Auto-resume:** If the AI provider drops the connection mid-reply, the server reconnects and asks the model to continue from exactly where it stopped, stitching the halves together.
- **🧠 Advanced AI Thinking:** Native support for reasoning models (like DeepSeek R1 and Qwen3) with an expandable "Thought Process" UI.
- **📱 Native Mobile Experience:** Seamless mobile UI with swipe-to-change message variants, exactly like native apps.
- **📌 Sketchboard System:** Pin important memories, rules, or context directly to the sidebar so the AI never forgets them.
- **📚 Auto-Summarization:** Built-in memory management that automatically summarizes old messages in the background to save context tokens.
- **🎭 Multi-Persona System:** Create and seamlessly switch between different AI characters or bots within the same session.
- **🔄 Character.AI Import:** Easily drag-and-drop your exported `.txt` chat histories from Character.AI directly into the engine.
- **🔌 Multi-Provider Support:** Plug in API keys from Groq, OpenRouter, Mistral, Cloudflare AI, Gemini, or any Custom OpenAI-compatible endpoint.

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
2. Click **API Endpoints** in the left sidebar.
3. Click **+ Add Endpoint**.
4. Select your provider (e.g., `Groq`), enter the Model ID (e.g., `llama-3.3-70b-versatile`), and paste your API Key.
5. Check the **Set as Primary** box and click **Save Key**.

### AI model names
- Chat model name: `google/gemma-4-26b-a4b-it`
- Summarize model name: `llama-3.3-70b-versatile`

### Recommended models
- OpenRouter: `nvidia/nemotron-3-super-120b-a12b:free`
- Gemini: `gemma-4-26b-a4b-it` and `gemma-4-31b-it`, both work well.

🎉 **You're done!** You can now go to "Current Chat" and start talking to your AI.

---

## ⬆️ Updating an existing installation

Your chats, personas and keys live in D1 and are kept across updates. The database schema upgrades itself on the first request after an update.

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

---

## ❓ Troubleshooting

- **"D1 database binding 'DB' not found"** — the `DB` binding is missing. Method B: redo Step 4. Method A: check `database_name` / `database_id` in `wrangler.toml` and deploy again (wrangler replaces the bindings with what is in that file).
- **Long replies stop partway / "Worker exceeded CPU time limit" in Observability** — you are running without the Durable Object. Switch to Method A.
- **A reply says "No reply was generated — your message was saved"** — the AI provider failed. Your message is kept; press **Retry**. Check the endpoint in **API Endpoints** with its **Test** button.
- **Where is the Durable Object?** — Dashboard → **Workers & Pages → Durable Objects** should list `ChatStreamer` after a Method A deploy, and the Worker's **Bindings** tab should show `STREAMER`.
