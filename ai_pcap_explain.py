#!/usr/bin/env python3
"""
Script that:
1) reads a .env file for OpenAI configuration,
2) runs `tshark -r <file> -T json` on the supplied trace file,
3) splits the packets into batches and analyzes each batch separately,
4) creates a final summary of all partial analyses,
5) saves summary to summary.txt and details to details.txt

Usage:
    python ai_pcap_explain.py <trace_file> [prompt] [--batch-size N]

If *prompt* is omitted, the script falls back to its default explanatory prompt.
"""

import argparse
import json
import os
import subprocess
import sys

try:
    from openai import OpenAI
except ImportError:
    print("❌  Missing dependency: install with `pip install openai`", file=sys.stderr)
    sys.exit(1)

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #

def load_env_file(env_path=".env"):
    """Parse a simple .env file (key=value) and return a dict."""
    env = {}
    if not os.path.isfile(env_path):
        raise FileNotFoundError(f"Environment file '{env_path}' not found.")
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue  # ignore malformed lines
            key, val = line.split("=", 1)
            env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def run_tshark(trace_file):
    """Run tshark and capture JSON output. Returns a string."""
    if not os.path.isfile(trace_file):
        raise FileNotFoundError(f"Trace file '{trace_file}' does not exist.")
    cmd = ["tshark", "-r", trace_file, "-T", "json"]
    try:
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise RuntimeError("`tshark` binary not found. Is Wireshark installed?")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"`tshark` failed with exit code {exc.returncode}:\n{exc.stderr}"
        )
    return result.stdout


def split_packets_into_batches(tshark_json, batch_size=10):
    """Split the JSON packet array into smaller batches."""
    try:
        packets = json.loads(tshark_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON from tshark: {exc}")
    
    if not isinstance(packets, list):
        raise ValueError("Expected JSON array from tshark")
    
    batches = []
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i + batch_size]
        batches.append(batch)
    
    return batches


def build_batch_prompt(batch_packets, batch_num, total_batches, trace_file, user_prompt=None):
    """Create a prompt string for analyzing a batch of packets."""
    batch_json = json.dumps(batch_packets, indent=2)
    
    if user_prompt:
        prompt = (
            f"Analizuję plik PCAP '{trace_file}' w porcjach.\n"
            f"To jest porcja {batch_num}/{total_batches} (pakiety {(batch_num-1)*len(batch_packets)+1}-{(batch_num-1)*len(batch_packets)+len(batch_packets)}).\n\n"
            f"Pytanie użytkownika: {user_prompt}\n\n"
            f"JSON dump tej porcji pakietów:\n{batch_json}\n\n"
            "Przeanalizuj tę porcję pakietów w kontekście pytania użytkownika. "
            "Skup się na kluczowych informacjach i wzorcach w tej porcji."
        )
    else:
        prompt = (
            f"Analizuję plik PCAP '{trace_file}' w porcjach.\n"
            f"To jest porcja {batch_num}/{total_batches} (pakiety {(batch_num-1)*len(batch_packets)+1}-{(batch_num-1)*len(batch_packets)+len(batch_packets)}).\n\n"
            f"JSON dump tej porcji pakietów:\n{batch_json}\n\n"
            "Przeanalizuj tę porcję pakietów i opisz co się dzieje w tej części komunikacji. "
            "Skup się na kluczowych informacjach: protokołach, adresach IP, portach, "
            "rodzaju komunikacji i wszelkich anomaliach czy wzorcach."
        )
    
    return prompt


def build_summary_prompt(batch_analyses, trace_file, user_prompt=None):
    """Create a prompt for the final summary."""
    analyses_text = "\n\n".join([
        f"=== Analiza porcji {i+1} ===\n{analysis}"
        for i, analysis in enumerate(batch_analyses)
    ])
    
    if user_prompt:
        prompt = (
            f"Mam analizy poszczególnych porcji pliku PCAP '{trace_file}'.\n"
            f"Pytanie użytkownika było: {user_prompt}\n\n"
            f"Analizy poszczególnych porcji:\n{analyses_text}\n\n"
            "Na podstawie wszystkich analiz cząstkowych, przygotuj kompleksowe podsumowanie "
            "odpowiadające na pytanie użytkownika. Połącz informacje z wszystkich porcji "
            "w spójną całość i wyciągnij najważniejsze wnioski."
        )
    else:
        prompt = (
            f"Mam analizy poszczególnych porcji pliku PCAP '{trace_file}'.\n\n"
            f"Analizy poszczególnych porcji:\n{analyses_text}\n\n"
            "Na podstawie wszystkich analiz cząstkowych, przygotuj kompleksowe podsumowanie "
            "całego ruchu sieciowego. Połącz informacje z wszystkich porcji w spójną całość, "
            "opisz główne wzorce komunikacji, protokoły, potencjalne problemy czy anomalie. "
            "Podsumowanie powinno dawać pełny obraz tego co działo się w sieci."
        )
    
    return prompt


def ask_openai(client: OpenAI, model: str, prompt: str):
    """Send a request to OpenAI and return the assistant's reply."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,   # keep it factual
            max_tokens=8192,
        )
    except Exception as exc:
        raise RuntimeError(f"OpenAI request failed: {exc}")

    return response.choices[0].message.content


def show_progress_bar(current, total, bar_length=50):
    """Display an ASCII progress bar."""
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    percent = 100 * current / total
    print(f'\r🤖 Analizuję: |{bar}| {percent:.1f}% ({current}/{total})', end='', flush=True)
    if current == total:
        print()  # New line when complete


def write_to_file(filename, content):
    """Write content to file with UTF-8 encoding."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as exc:
        print(f"❌  Błąd zapisu do {filename}: {exc}", file=sys.stderr)
        return False


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Explain a pcap trace using OpenAI with batch processing."
    )
    parser.add_argument("trace_file", help="Path to the .pcap file")
    parser.add_argument(
        "prompt",
        nargs="?",
        default=None,
        help="Optional user‑supplied prompt/question about the trace",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Number of packets per batch (default: 10)"
    )
    args = parser.parse_args()

    # 1. Load env
    try:
        cfg = load_env_file()
    except Exception as exc:
        print(f"❌  {exc}", file=sys.stderr)
        sys.exit(1)

    required_keys = ["OPENAI_ENDPOINT", "OPENAI_API_KEY", "MODEL"]
    missing = [k for k in required_keys if k not in cfg]
    if missing:
        print(
            f"❌  Missing keys in .env: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    endpoint = cfg["OPENAI_ENDPOINT"]
    api_key = cfg["OPENAI_API_KEY"]
    model = cfg["MODEL"]

    # 2. Run tshark
    try:
        print(f"🔍 Uruchamiam tshark na pliku '{args.trace_file}'...")
        tshark_output = run_tshark(args.trace_file)
    except Exception as exc:
        print(f"❌  {exc}", file=sys.stderr)
        sys.exit(1)

    # 3. Split into batches
    try:
        print(f"📦 Dzielę pakiety na porcje po {args.batch_size}...")
        batches = split_packets_into_batches(tshark_output, args.batch_size)
        print(f"📊 Znaleziono {sum(len(batch) for batch in batches)} pakietów w {len(batches)} porcjach")
    except Exception as exc:
        print(f"❌  {exc}", file=sys.stderr)
        sys.exit(1)

    if not batches:
        print("❌  Brak pakietów do analizy", file=sys.stderr)
        sys.exit(1)

    # 4. Initialize OpenAI client
    client = OpenAI(api_key=api_key, base_url=endpoint.rstrip("/") + "/v1")

    # 5. Process each batch with progress bar
    batch_analyses = []
    print("🚀 Rozpoczynam analizę porcji...")
    
    for i, batch in enumerate(batches):
        show_progress_bar(i, len(batches))
        
        prompt = build_batch_prompt(
            batch, i+1, len(batches), args.trace_file, args.prompt
        )
        
        try:
            analysis = ask_openai(client, model, prompt)
            batch_analyses.append(analysis)
        except Exception as exc:
            print(f"\n❌  Błąd analizy porcji {i+1}: {exc}", file=sys.stderr)
            sys.exit(1)
    
    # Update progress bar to complete
    show_progress_bar(len(batches), len(batches))

    # 6. Generate final summary
    print("🎯 Tworzę końcowe podsumowanie...")
    summary_prompt = build_summary_prompt(batch_analyses, args.trace_file, args.prompt)
    
    try:
        final_summary = ask_openai(client, model, summary_prompt)
    except Exception as exc:
        print(f"❌  Błąd tworzenia podsumowania: {exc}", file=sys.stderr)
        sys.exit(1)

    # 7. Prepare detailed analysis content
    detailed_content = []
    for i, analysis in enumerate(batch_analyses, 1):
        detailed_content.append(f"=== ANALIZA PORCJI {i}/{len(batch_analyses)} ===\n{analysis}")
    
    details_text = "\n\n".join(detailed_content)

    # 8. Save to files
    print("💾 Zapisuję wyniki do plików...")
    
    summary_saved = write_to_file("summary.txt", final_summary)
    details_saved = write_to_file("details.txt", details_text)
    
    if summary_saved:
        print("✅ Podsumowanie zapisane do: summary.txt")
    if details_saved:
        print("✅ Szczegóły zapisane do: details.txt")

    # 9. Display results on screen
    print("\n" + "="*80)
    print("🎯 KOŃCOWE PODSUMOWANIE ANALIZY")
    print("="*80)
    print(final_summary)
    
    if not (summary_saved and details_saved):
        print("\n" + "="*80)
        print("📋 SZCZEGÓŁOWE ANALIZY PORCJI")
        print("="*80)
        print(details_text)


if __name__ == "__main__":
    main()