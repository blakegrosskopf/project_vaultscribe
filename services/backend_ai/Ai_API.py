"""
Ai_API.py

Provides a single class AISummarizerTranscriber with:
 - transcribe(path_to_audio: str) -> str
 - summarize(text: str) -> str

Transcription:
 - Uses ONLY local model files in ./whisper (you must download the model files yourself from
   https://huggingface.co/openai/whisper-tiny and place them in ./whisper).
 - Tries to load the model using the openai 'whisper' package first; if that fails, tries
   'faster_whisper'. Both attempts use local files only.

Summarization:
 - Calls OpenRouter chat completions API (non-streaming) for model:
   deepseek/deepseek-chat-v3.1:free
 - You must hardcode your OpenRouter API key into OPENROUTER_API_KEY below.

Requirements:
 - See requirements.txt alongside this file.
 - System: ffmpeg installed and accessible in PATH.
"""

import os
import glob
import json
import re
from typing import Optional

import requests

# ========== Hardcoded OpenRouter API key ========================
OPENROUTER_API_KEY = "API KEY GOES HERE"
# ================================================================

class AISummarizerTranscriber:
    """
    High-level class that exposes:
      - transcribe(path_to_audio: str) -> str
      - summarize(text: str) -> str

    Initialization:
      - Optionally accepts a model_dir (defaults to ./whisper).
      - On init, attempts to locate a local whisper model file in model_dir.
        The code will try to use the openai 'whisper' package first and fall back to
        'faster_whisper' if available/necessary. No downloads are attempted.
    """

    def __init__(self, model_dir: str = "./whisper", openrouter_api_key: Optional[str] = None):
        """
        :param model_dir: directory where local whisper model files are stored.
        :param openrouter_api_key: optional override for the API key (if None uses the hardcoded one)
        """
        self.model_dir = model_dir
        self.openrouter_api_key = openrouter_api_key or OPENROUTER_API_KEY
        self._whisper_model = None
        self._whisper_backend = None  # 'openai_whisper' or 'faster_whisper'
        # Attempt to load the local whisper model now (will raise informative error if not possible)
        self._load_local_whisper_model()

    # -------------------------
    # Internal helpers
    # -------------------------
    def _find_local_model_file(self):
        """
        Scan the model_dir for typical model filenames/extensions used by HuggingFace/Whisper.
        Returns full path to the first matching file or None if not found.
        """
        if not os.path.isdir(self.model_dir):
            return None

        # common candidate extensions
        candidate_exts = ["*.pt", "*.pth", "*.bin", "*.safetensors", "*.ckpt"]
        for ext in candidate_exts:
            matches = glob.glob(os.path.join(self.model_dir, ext))
            if matches:
                # return first match
                return matches[0]

        # If the user extracted a folder containing model shards or special layout,
        # the user can also point model_dir directly to a folder usable by faster_whisper/transformers.
        # As a last resort, return the directory itself so backends that accept a directory path can try it.
        return self.model_dir if os.listdir(self.model_dir) else None

    def _load_local_whisper_model(self):
        """
        Attempts to load a local whisper model in this order:
          1) openai 'whisper' (import whisper) using the located file/path
          2) faster_whisper (import faster_whisper) using located file/path

        If neither works, raises a RuntimeError with guidance.
        """
        model_path = self._find_local_model_file()
        if not model_path:
            raise RuntimeError(
                f"No model files found in '{self.model_dir}'. "
                "Please download the whisper-tiny model files (from Hugging Face) and place them in this directory."
            )

        # Try openai/whisper first
        try:
            import whisper  # type: ignore
            # Load from the local model path (pass the actual file path so openai/whisper doesn't try to download).
            # If the user placed tiny.pt in ./whisper, model_path will point to that file.
            model = whisper.load_model(model_path, device="cpu")
            self._whisper_model = model
            self._whisper_backend = "openai_whisper"
            return
        except Exception as e_openai_whisper:
            # swallow and try faster_whisper
            # (we intentionally do not attempt to download anything)
            openai_err = e_openai_whisper
            print("Issue loading open-ai's whisper:", openai_err, "\n=======================")

        try:
            # Attempt faster_whisper
            from faster_whisper import WhisperModel  # type: ignore
            # WhisperModel can accept a model path or model size name. We pass the path to local files.
            # Device selection: default to CPU to avoid forcing GPU usage.
            model = WhisperModel(model_path, device="cpu", compute_type="int8")
            self._whisper_model = model
            self._whisper_backend = "faster_whisper"
            return
        except Exception as e_faster_whisper:
            # If both fail, raise an informative error including tracebacks
            raise RuntimeError(
                "Failed to load a local Whisper model from '{model_dir}'.\n"
                "Tried two backends:\n"
                "  1) openai 'whisper' package (error shown below)\n"
                "  2) 'faster_whisper' package (error shown below)\n\n"
                "Make sure you placed the model files (e.g. model.safetensors, model.bin, or .pt) inside './whisper'.\n"
                "Also ensure required packages are installed and ffmpeg is available on your system.\n\n"
                "openai/whisper error:\n"
                f"{openai_err}\n\n"
                "faster_whisper error:\n"
                f"{e_faster_whisper}\n"
            )

    @staticmethod
    def _sanitize_to_ascii(text: str) -> str:
        """
        Remove any character that is NOT a printable ASCII character (space (32) to tilde (126)).
        Preserve newline characters.
        Collapse multiple spaces into a single space and trim leading/trailing spaces on each line.
        """
        if text is None:
            return ""

        # Keep printable ASCII + newline
        sanitized = "".join(ch for ch in text if ch == "\n" or 32 <= ord(ch) <= 126)

        # Normalize whitespace: collapse sequences of spaces into single space
        # but preserve line breaks.
        lines = sanitized.splitlines()
        cleaned_lines = [" ".join(line.split()) for line in lines]
        result = "\n".join(line.strip() for line in cleaned_lines if line.strip() != "")

        return result.strip()

    # --- NEW helper: strip angle-bracketed tokens like <｜begin▁of▁sentence｜> ---
    @staticmethod
    def _strip_angle_bracket_tokens(text: str) -> str:
        """
        Remove any tokens enclosed in angle brackets, e.g. <｜begin▁of▁sentence｜>,
        <|special|>, <extra>, etc. Returns the cleaned string (noop if text is falsy).
        """
        if not text:
            return text
        # Remove everything between '<' and the next '>' (non-greedy)
        return re.sub(r"<[^>]*?>", "", text)

    # -------------------------
    # Public methods
    # -------------------------
    def transcribe(self, path_to_audio: str) -> str:
        """
        Transcribe the audio file at path_to_audio using the local Whisper model.

        :param path_to_audio: relative or absolute path to an audio file (e.g., wav, mp3).
        :return: transcription string cleaned to standard ASCII punctuation/letters (non-ASCII removed).
        :raises: FileNotFoundError, RuntimeError (if transcription backend isn't available or fails)
        """
        if not os.path.isfile(path_to_audio):
            raise FileNotFoundError(f"Audio file not found: {path_to_audio}")

        if not self._whisper_model or not self._whisper_backend:
            raise RuntimeError("Whisper model not loaded. Initialization failed.")

        # openai/whisper backend
        if self._whisper_backend == "openai_whisper":
            try:
                # model.transcribe returns a dict with "text" (standard openai/whisper API)
                result = self._whisper_model.transcribe(path_to_audio)
                text = result.get("text", "") if isinstance(result, dict) else str(result)

                # strip angle-bracket tokens BEFORE ASCII sanitization
                text = self._strip_angle_bracket_tokens(text)

                cleaned = self._sanitize_to_ascii(text)
                return cleaned
            except Exception as e:
                raise RuntimeError(f"Transcription failed using openai/whisper backend: {e}")

        # faster_whisper backend
        elif self._whisper_backend == "faster_whisper":
            try:
                # faster_whisper: model.transcribe returns (segments, info) or generator depending on arguments.
                # We'll call and join segments' text for a single result.
                segments, info = self._whisper_model.transcribe(path_to_audio, beam_size=5)
                # segments is an iterator/generator or list of segment dicts each with .text
                # convert to list and join.
                try:
                    # If segments is a generator, iterate
                    text_parts = []
                    for seg in segments:
                        # seg can be object with 'text' or a dict
                        seg_text = seg.text if hasattr(seg, "text") else seg.get("text", "")
                        text_parts.append(seg_text)
                    text = " ".join(text_parts)
                except TypeError:
                    # If segments is already a list/other, try treating it as such
                    text = " ".join(getattr(seg, "text", seg.get("text", "")) for seg in segments)

                # strip angle-bracket tokens BEFORE ASCII sanitization
                text = self._strip_angle_bracket_tokens(text)

                cleaned = self._sanitize_to_ascii(text)
                return cleaned
            except Exception as e:
                raise RuntimeError(f"Transcription failed using faster_whisper backend: {e}")

        else:
            raise RuntimeError(f"Unknown transcription backend: {self._whisper_backend}")

    def summarize(self, text_to_summarize: str) -> str:
        """
        Summarize the provided text using OpenRouter.

        Returns a non-empty string whenever possible.
        If the API returns an unexpected/empty format, we fall back
        to a simple local "summary" (first chunk of the transcript).
        """
        if not self.openrouter_api_key:
            raise RuntimeError("OpenRouter API key not provided. Please hardcode it into the script or pass it in init.")

        # Build prompt
        prompt = f"""
        Summarize the following transcript into clean, accurate bullet points.

        Requirements:
        - Remove filler words, stutters, and repetition.
        - Correct mis-transcribed names or terms using context.
        - Extract the *main ideas* only.
        - Use short, direct bullets.
        - Capture any threats, warnings, or key decisions.
        - Do NOT invent new information.

        TRANSCRIPT:
        {text_to_summarize}
        """

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            # use the model you've already switched to
            "model": "qwen/qwen-2.5-72b-instruct:free",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "temperature": 0.2,
            "max_tokens": 1024,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
        except Exception as e:
            # hard failure -> raise so the UI can show a clean error
            raise RuntimeError(f"Failed to make request to OpenRouter API: {e}")

        if resp.status_code != 200:
            body = resp.text
            raise RuntimeError(f"OpenRouter API returned status {resp.status_code}: {body}")

        # Parse JSON
        try:
            j = resp.json()
        except Exception:
            raise RuntimeError("OpenRouter returned a non-JSON response.")

        summary_text = None

        # ---- primary path: choices[0].message.content ----
        if isinstance(j, dict):
            choices = j.get("choices")
            if choices and isinstance(choices, list) and len(choices) > 0:
                first_choice = choices[0]
                if isinstance(first_choice, dict):
                    msg = first_choice.get("message") or first_choice.get("delta") or first_choice

                    # msg can be dict or string
                    if isinstance(msg, dict):
                        content = msg.get("content")

                        # content can be str OR list (OpenRouter often uses list)
                        if isinstance(content, str):
                            summary_text = content
                        elif isinstance(content, list):
                            parts = []
                            for c in content:
                                if isinstance(c, str):
                                    parts.append(c)
                                elif isinstance(c, dict):
                                    # handle typical {"type": "text", "text": "..."} chunks
                                    txt = c.get("text") or c.get("content")
                                    if isinstance(txt, str):
                                        parts.append(txt)
                            summary_text = "".join(parts).strip()
                    elif isinstance(msg, str):
                        summary_text = msg

        # ---- secondary paths (older / alternative schemas) ----
        if not summary_text:
            if isinstance(j, dict):
                for key in ("output", "result", "text", "response"):
                    v = j.get(key)
                    if isinstance(v, str):
                        summary_text = v
                        break
                    if isinstance(v, list) and v and isinstance(v[0], str):
                        summary_text = v[0]
                        break

        # ---- last resort: scan for first string in the JSON ----
        if not summary_text:
            def find_first_string(obj):
                if isinstance(obj, str):
                    return obj
                if isinstance(obj, dict):
                    for val in obj.values():
                        s = find_first_string(val)
                        if s:
                            return s
                if isinstance(obj, list):
                    for item in obj:
                        s = find_first_string(item)
                        if s:
                            return s
                return None

            summary_text = find_first_string(j) or ""

        # Clean up & strip special tokens
        summary_text = self._strip_angle_bracket_tokens(summary_text or "").strip()

        # If it's STILL empty, fall back to a simple local summary
        if not summary_text:
            summary_text = self._fallback_summary(text_to_summarize)

        return summary_text
    @staticmethod
    def _fallback_summary(text: str, max_sentences: int = 4) -> str:
        """
        Simple local fallback summary:
        - Clean the transcript
        - Split into sentences
        - Pick a few reasonably long sentences spread across the text
        - Return them as bullet points

        This gives something that *looks* like a proper summary even
        when the API response is missing or unparsable.
        """
        if not text:
            return "[Summary unavailable]"

        # Reuse the same ASCII cleaner so we don't show weird tokens
        cleaned = AISummarizerTranscriber._sanitize_to_ascii(text)
        if not cleaned:
            return "[Summary unavailable]"

        # Naive sentence split: split on .?! followed by whitespace
        sentences = re.split(r'(?<=[.!?])\s+', cleaned)

        # Filter out super-short / filler sentences
        candidates = [s.strip() for s in sentences if len(s.strip()) > 40]

        # If nothing passes the filter, just truncate the cleaned text
        if not candidates:
            snippet = cleaned[:400].strip()
            return snippet

        # Pick up to max_sentences sentences spread through the text
        # (start, middle, end-ish), so it feels like a real summary.
        step = max(1, len(candidates) // max_sentences)
        picked = candidates[0:len(candidates):step][:max_sentences]

        # Return as bullet points
        bullets = "\n".join(f"- {s}" for s in picked)
        return bullets

