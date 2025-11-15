# VaultScribe Desktop (LoginSystemDesktop)

VaultScribe Desktop is a **secure, local-first meeting assistant**.  
It lets you:

- Sign in with a locally stored account (no cloud auth)
- Transcribe meeting audio **fully offline** using a local Whisper model
- Summarize transcripts via an **external LLM API** (OpenRouter)
- Securely view and copy stored transcripts and summaries

> ⚠️ **Important:** This project is a prototype for a class / portfolio, **not** production-ready security software.

---

## Features

- 🧑‍💻 **Local-first login**
  - User accounts stored locally  
  - Passwords hashed with **Argon2id**  
  - Time-limited auth tokens  

- 🔐 **Security-focused design**
  - No passwords or audio ever leave the machine  
  - Only **text transcripts** are sent to the summarization API  
  - Designed to run on a single trusted local device  

- 🎙 **Offline transcription**
  - Powered by a local **Whisper Tiny** model  
  - No cloud calls  
  - Requires `ffmpeg`  

- 🧾 AI summaries of meetings
  - Summaries generated using an LLM via **OpenRouter**  
  - You manually supply an API key inside `Ai_API.py`:
    ```
    OPENROUTER_API_KEY = "API KEY GOES HERE"
    ```

- 🗄 **Storage & retrieval**
  - View all saved meetings  
  - Inspect transcript + summary  
  - Text is fully copyable for documentation or support tickets  

---

## Tech Stack

- Python 3.10+
- Kivy + KivyMD (desktop UI)
- Argon2id hashing
- Whisper / faster_whisper
- OpenRouter API for summarization
- SQLite local database

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

### 2. Create and activate a venv

```bash
python -m venv .venv
```

**Windows:**
```bash
.venv\Scripts\activate
```

**macOS/Linux:**
```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install FFmpeg

**Windows:**
```bash
choco install ffmpeg
```

**macOS:**
```bash
brew install ffmpeg
```

**Linux:**
```bash
sudo apt install ffmpeg
```

### 5. Add a Whisper model

Create:

```
./whisper/
```

Download a Whisper Tiny model (from HuggingFace etc.) and place the `.pt` or `.bin` file into that folder.

### 6. Add your OpenRouter API key

Inside `Ai_API.py`:

```
OPENROUTER_API_KEY = "API KEY GOES HERE"
```

Replace with your key (but **do not commit it**).

---

## Running the App

```bash
python services/Main.py
```

---

## Usage Overview

### 🔐 Create an account
- Enter email and password  
- Password stored as Argon2id hash  

### 🔑 Sign in
- Validates credentials  
- Generates local session token  

### 🎙 Transcribe audio
- Pick a file  
- Whisper transcribes offline  
- Transcript sent to OpenRouter for summary  
- Summary displayed in a copyable text field  

### 🗄 View saved meetings
- Shows all stored sessions  
- Click any item for transcript + summary  

---

## Security Notes

- Argon2id password hashing  
- Offline transcription  
- Only text transcript goes to API  
- Local storage with SQLite  
- Not production-hardened  

---

## Future Improvements

- ENV-based secret management  
- Local summarization model  
- Export meeting files  
- Advanced search  

---

## License

MIT License

---

## Credits

- Kivy / KivyMD  
- Whisper  
- OpenRouter  
- Argon2id hashing  
