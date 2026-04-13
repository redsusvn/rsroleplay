# 🚀 RSROLEPLAY Engine

A lightning-fast, fully serverless AI chat platform powered by **Cloudflare Workers** and **Cloudflare D1**. Build your own private, customizable AI roleplay hub with zero hosting costs.

**Built by [@redsus.vn](https://miku.us.kg) |  Follow my tiktok for more info [https://www.tiktok.com/@redsusvn](https://www.tiktok.com/@redsusvn)**

---

## ✨ Features

- **⚡ 100% Serverless:** Runs entirely on Cloudflare's Edge (Workers + D1 Database). No traditional VPS or backend required.
- **🧠 Advanced AI Thinking:** Native support for reasoning models (like DeepSeek R1 and Qwen3) with an expandable "Thought Process" UI.
- **📱 Native Mobile Experience:** Seamless mobile UI with swipe-to-change message variants, exactly like native apps.
- **📌 Sketchboard System:** Pin important memories, rules, or context directly to the sidebar so the AI never forgets them.
- **📚 Auto-Summarization:** Built-in memory management that automatically summarizes old messages in the background to save context tokens.
- **🎭 Multi-Persona System:** Create and seamlessly switch between different AI characters or bots within the same session.
- **🔄 Character.AI Import:** Easily drag-and-drop your exported `.txt` chat histories from Character.AI directly into the engine.
- **🔌 Multi-Provider Support:** Plug in API keys from Groq, OpenRouter, Mistral, Cloudflare AI, or any Custom OpenAI-compatible endpoint.

---

## 🛠️ Installation Guide

Follow these steps to deploy your own instance in under 5 minutes. 

### Prerequisites
- A [Cloudflare](https://dash.cloudflare.com) account (Free tier is perfect).
- An API Key from an AI provider (e.g., [GroqCloud](https://console.groq.com/home)).

### Step 1: Create a Cloudflare Worker
1. Log in to your Cloudflare Dashboard.
2. On the left sidebar, navigate to **Workers & Pages**.
3. Click **Create** -> **Create Worker**.
4. Name your worker (e.g., `myownchatplatform`) and click **Deploy**.

### Step 2: Paste the Source Code
1. Once deployed, click **Edit Code** on your new Worker.
2. Delete all the default code in `worker.js`.
3. Copy the entire JavaScript source code from this repository and paste it in.
4. Click **Deploy** in the top right corner.

### Step 3: Create the D1 Database
1. Go back to the main Cloudflare Dashboard sidebar.
2. Expand **Storage & databases** and click **D1 SQL database**.
3. Click **Create Database**.
4. Give it a memorable name (e.g., `rsroleplay-db`) and click **Create**.

### Step 4: Bind the Database (Crucial Step ⚠️)
1. Go back to **Workers & Pages** and click on your Worker.
2. Go to the **Settings** tab, then click **Bindings**.
3. Click **Add Binding** and select **D1 database**.
4. **Variable name:** Type exactly `DB` *(Must be fully capitalized!)*
5. **D1 database:** Select the database you created in Step 3.
6. Click **Deploy / Save**.

### Step 5: Initial Setup & Admin Account
1. Click the **Visit** button (or open your Worker's `.workers.dev` URL in your browser).
2. You will be greeted by the First Time Setup screen.
3. Enter your desired Admin Username and Password. 
   > *Note: You can only create ONE account for this private instance. Keep your credentials safe!*

### Step 6: Connect your AI (API Endpoints)
1. Log in to your RSROLEPLAY instance.
2. Click **API Endpoints** in the left sidebar.
3. Click **+ Add Endpoint**.
4. Select your provider (e.g., `Groq`), enter the Model ID (e.g., `llama-3.3-70b-versatile`), and paste your API Key.
5. Check the **Set as Primary** box and click **Save Key**.

AI MODAL NAME: 
- Chat modal name: google/gemma-4-26b-a4b-it
- Summarize modal name: llama-3.3-70b-versatile




🎉 **You're done!** You can now go to "Current Chat" and start talking to your AI.

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
