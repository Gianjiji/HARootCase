#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# HAR Universal Analyzer — macOS Drag & Drop Launcher
# ══════════════════════════════════════════════════════════════════════════════
#
# USO:
#   1. Doppio-click su questo file per analizzare tutti i .har nella stessa cartella
#   2. Trascina (drag & drop) uno o piu' file .har su questo file nel Finder
#
# Il file .command e' eseguibile nativamente su macOS con doppio-click.
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANALYZER="${SCRIPT_DIR}/har_analyzer_pro.py"

# Verifica che Python 3 sia disponibile
if ! command -v python3 &> /dev/null; then
    echo "ERRORE: python3 non trovato. Installarlo con: brew install python3"
    echo ""
    echo "Premi un tasto per chiudere..."
    read -n 1
    exit 1
fi

# Verifica che lo script esista
if [ ! -f "$ANALYZER" ]; then
    echo "ERRORE: har_analyzer_pro.py non trovato in: ${SCRIPT_DIR}"
    echo ""
    echo "Premi un tasto per chiudere..."
    read -n 1
    exit 1
fi

echo ""

if [ $# -gt 0 ]; then
    # File passati via drag & drop
    python3 "$ANALYZER" "$@"
else
    # Nessun file: analizza la directory dello script
    python3 "$ANALYZER" "${SCRIPT_DIR}"
fi

echo ""
echo "────────────────────────────────────────────────────────────────"
echo "  Premi un tasto per chiudere questa finestra..."
echo "────────────────────────────────────────────────────────────────"
read -n 1
