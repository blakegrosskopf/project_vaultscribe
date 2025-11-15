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
OPENROUTER_API_KEY = ""
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
        Summarize the provided text using OpenRouter's deepseek/deepseek-chat-v3.1:free model.

        Implementation notes:
         - Constructs a single prompt that instructs the model to summarize the provided text.
         - Sends a single non-streaming request and waits for completion.
         - Returns the model's top-level reply as a string.

        :param text_to_summarize: the text to be summarized (the user's input param).
        :return: model reply as a string
        :raises: RuntimeError on HTTP/API failures or missing API key
        """
        if not self.openrouter_api_key:
            raise RuntimeError("OpenRouter API key not provided. Please hardcode it into the script or pass it in init.")

        # Build the prompt - combine the summarization instruction and the user's text in one message.
        prompt = (
            "Please summarize the following text clearly and concisely. "
            "Provide the main points, and keep it readable and well-structured. Do NOT introduce the task with phrases like 'Certainly, let's do that' -- instead, just jump straight into the summary.\n\n"
            f"TEXT TO SUMMARIZE:\n\n{text_to_summarize}"
        )

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": "deepseek/deepseek-chat-v3.1:free",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            # non-streaming call
            "stream": False,
            # optional tuning
            "temperature": 0.2,
            "max_tokens": 1024,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
        except Exception as e:
            raise RuntimeError(f"Failed to make request to OpenRouter API: {e}")

        if resp.status_code != 200:
            # try to include any helpful body
            body = resp.text
            raise RuntimeError(f"OpenRouter API returned status {resp.status_code}: {body}")

        """
        # For debugging only
        print("STATUS:", resp.status_code)
        print("HEADERS:", resp.headers)
        print("BODY (first 500 chars):")
        print(resp.text[:500])
        """

        try:
            j = resp.json()
        except Exception:
            raise RuntimeError("OpenRouter returned a non-JSON response.")

        # The response schema is expected to be similar to Chat Completions:
        # Try several common fields for maximum compatibility.
        summary_text = None

        # Common field: choices[0].message.content
        try:
            if isinstance(j, dict) and "choices" in j and len(j["choices"]) > 0:
                first_choice = j["choices"][0]
                # typical openai-style
                if isinstance(first_choice, dict):
                    msg = first_choice.get("message") or first_choice.get("delta") or first_choice
                    if isinstance(msg, dict):
                        # message.content or msg.get("content")
                        if "content" in msg and isinstance(msg["content"], str):
                            summary_text = msg["content"]
                        elif "text" in msg and isinstance(msg["text"], str):
                            summary_text = msg["text"]
                    elif isinstance(msg, str):
                        summary_text = msg
        except Exception:
            pass

        # Alternative: direct 'output' or 'result' fields
        if summary_text is None:
            for key in ("output", "result", "text", "response"):
                v = j.get(key) if isinstance(j, dict) else None
                if isinstance(v, str):
                    summary_text = v
                    break
                # sometimes it's nested
                if isinstance(v, list) and len(v) > 0 and isinstance(v[0], str):
                    summary_text = v[0]
                    break

        # As a last resort, stringify the whole JSON (but this is probably not desired)
        if summary_text is None:
            # try to extract any string value deeply (best-effort)
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

        # strip angle-bracket tokens BEFORE trimming/returning
        summary_text = self._strip_angle_bracket_tokens(summary_text or "")

        return summary_text.strip()

# ===========================
# Example usage (commented)
# ===========================
if __name__ == "__main__":
    # Example quick test; uncomment and adjust paths as needed.
    # Make sure to set OPENROUTER_API_KEY above before calling summarize.
    print("Working...\n")
    
    tst = AISummarizerTranscriber(model_dir="./whisper")
    transcript = tst.transcribe("./transcription_test.wav")
    print("TRANSCRIPT:\n", transcript)
    summary = tst.summarize(transcript)
    print("\nSUMMARY:\n", summary)
    
    # print("Module loaded. Create an AISummarizerTranscriber instance to transcribe/summarize.")
