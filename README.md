# 🚀 HARootCase v0.1 – Enterprise Edition

Suite diagnostica **enterprise** per l'analisi automatizzata di file HTTP Archive (HAR), con rilevamento anomalie differenziale, scansione sicurezza e reportistica forense.

HARootCase è pensato per SRE, DevOps e Security Engineer che devono capire rapidamente *perché* una pagina web è lenta, rotta o si comporta in modo diverso tra ambienti (es. OK in staging, KO in produzione).

---

## 🎯 Obiettivi

- Diagnosticare problemi complessi di caricamento pagina (SPA, API, asset statici).
- Confrontare tracce **OK vs KO** per isolare rapidamente la causa radice.
- Individuare **problemi di sicurezza** (PII leak, cookie, header) direttamente dal traffico.
- Generare un **report HTML standalone**, pronto per condivisione interna o allegato a ticket.

---

## 🧠 Motore Diagnostico Intelligente

- **Health Scoring (0–100)**
  Ogni file HAR riceve un punteggio di salute e una label:
  - `HEALTHY`
  - `DEGRADED`
  - `BROKEN`
  Il punteggio tiene conto di:
  - errori HTTP 4xx/5xx
  - timeouts e problemi di rete
  - incompletezza del caricamento
  - colli di bottiglia di performance (TTFB, download, risorse pesanti)

- **Dynamic Rule Engine**
  Il programma carica una *Knowledge Base* JSON (`har_known_issues.json`) che contiene pattern di problemi noti, ad esempio:
  - **HTTP/2 Multiplexing Stall**
  - **SSL Handshake Failure**
  - cache-control deboli o mancanti
  - pattern tipici di errori SPA/API

- **Root Cause Analysis**
  Viene generata una diagnosi in linguaggio naturale che prova a spiegare il *perché* del malfunzionamento, ad esempio:
  > "Il bundle JS principale non viene caricato nel tracciato KO, causando il mancato rendering della SPA."

---

## ⚔️ Analisi Differenziale (OK vs KO)

Quando sono presenti sia HAR "sani" che "rotti", il tool entra in modalità **Differential Analysis** e:

- confronta un HAR di riferimento (OK) con uno o più HAR problematici (KO)
- identifica:
  - risorse **mancanti nel KO** (`MISSING_IN_KO`)
  - differenze di **status code** (es. 200 in OK vs 404/500 in KO)
  - regressioni di latenza e TTFB
  - differenze su protocollo, caching e compressione

Questo è particolarmente utile in casi come:

- "Funziona in Chrome ma non in Safari"
- "Funziona in staging ma non in produzione"
- "Alcuni utenti vedono pagina bianca, altri no"

---

## 🛡️ Security & Privacy Scanner

HARootCase integra una scansione di sicurezza e privacy sui tracciati:

- **PII Detection**
  - email
  - numeri di carte di credito
  - token JWT / Bearer
  - API key in query string o header

- **Security Headers Audit**
  - CSP (Content-Security-Policy)
  - HSTS
  - X-Frame-Options
  - altri header di sicurezza comuni

- **Cookie Forensics**
  - verifica flag `Secure`, `HttpOnly`, `SameSite`
  - evidenzia cookie potenzialmente insicuri o esposti

I risultati vengono riportati sia in console sia nella sezione Security del report HTML.

---

## 📊 Report HTML Enterprise

Alla fine dell'analisi, il programma genera un **report HTML standalone** (un solo file, nessuna dipendenza esterna) che può essere:

- allegato a ticket Jira/ServiceNow
- condiviso tra team (SRE, Dev, Security, Management)
- archiviato per scopi forensi o di audit

Struttura del report:

1. **Header & Executive Summary**
   - titolo, versione, timestamp
   - panoramica sullo stato complessivo (quanti file HEALTHY / DEGRADED / BROKEN)
   - riepilogo delle anomalie critiche e ad alta priorità
   - elenco di **azioni correttive suggerite** (prioritizzate per impatto/complessità)

2. **Score Cards**
   - una card per ogni file HAR con:
     - gauge circolare Health Score 0–100
     - label di stato (`HEALTHY`, `DEGRADED`, `BROKEN`)
     - motivazioni principali del punteggio

3. **Technical Deep Dive**
   - **Waterfall SVG** per ogni HAR (blocked, DNS, connect, SSL, wait, receive)
   - **Performance** (TTFB P50/P90/P99, download P50/P90/P99, KB totali, risorse non compresse)
   - **Security** (PII, header mancanti, cookie insicuri)
   - **KB Matches** (pattern noti triggerati dalla Knowledge Base)
   - **Root Cause Analysis** (testo in chiaro con la causa probabile)

---

## 📋 Requisiti

- **Python:** 3.7+
- **Dipendenze:** solo Standard Library (nessun `pip install` richiesto)
  - `json`, `re`, `html`, `urllib`, `argparse`, `dataclasses`, ecc.
- **OS:** Windows, macOS, Linux
- **Browser:** qualsiasi browser moderno per la visualizzazione del report

---

## ▶️ Utilizzo Base

### Auto-discovery nella directory corrente

Analizza tutti i file `.har` trovati nella directory corrente (ed eventuali sottocartelle convenzionali):

```bash
python3 HARootCase.py
```

### Analisi di file specifici

```bash
# Uno o più file HAR
python3 HARootCase.py login_ok.har login_ko.har
```

### Analisi di una cartella

```bash
python3 HARootCase.py ./har_captures
```

---

## ⚙️ Opzioni CLI principali

```bash
# Soglia di latenza personalizzata (ms) per evidenziare lentezze critiche
python3 HARootCase.py --latency 2000 ./har_captures

# Non generare il report HTML (solo output da console)
python3 HARootCase.py --no-html problematico.har

# Non aprire automaticamente il report nel browser
python3 HARootCase.py --no-open problematico.har

# Salta l'analisi di sicurezza
python3 HARootCase.py --no-security problematico.har

# Salta l'analisi di performance
python3 HARootCase.py --no-performance problematico.har
```

Se non fornisci alcun percorso, lo strumento prova a scoprire automaticamente i file `.har` nella cartella corrente e in sottocartelle come `./HAR`.

---

## 🤖 Local AI RCA (opzionale)

HARootCase può attivare un **layer AI locale e offline** che agisce come *revisore/analista* sopra i risultati già prodotti dal motore deterministico. Non sostituisce il motore: lo arricchisce con una review critica della root cause, valutazione della confidenza, cause alternative, contraddizioni/ambiguità e una remediation prioritaria.

> ⚠️ **Nessuna chiamata cloud.** Il layer è completamente opzionale, usa solo la *standard library* (`urllib`) e parla con un LLM locale tramite l'API compatibile **Ollama**. Il motore deterministico resta sempre la **fonte primaria**; l'AI serve solo per review, ambiguità e remediation. Il report HTML viene generato comunque anche se l'AI fallisce.

### Prerequisito: Ollama

Installa [Ollama](https://ollama.com) e scarica un modello locale:

```bash
ollama pull llama3.1:8b
```

### Esempi

```bash
# Analisi differenziale con review AI locale (modello di default llama3.1:8b)
python3 HARootCase.py login_ok.har login_ko.har --local-ai

# Cartella di catture con un modello custom
python3 HARootCase.py ./har_captures --local-ai --local-ai-model mistral:7b

# Solo console + JSON AI (nessun report HTML)
python3 HARootCase.py problematico.har --local-ai --no-html
```

Quando `--local-ai` è attivo viene prodotto un **JSON AI separato** (`<report>_local_ai.json` oppure `HARootCase_<timestamp>_local_ai.json`) e, se il report HTML è abilitato, una nuova sezione **"AI Local RCA Review"** viene aggiunta dopo la Root Cause Analysis.

### Privacy & sicurezza

- Nessuna dipendenza nuova obbligatoria, nessuna chiamata di rete verso il cloud.
- Di default **non** vengono inviati body o header completi al modello: solo metadati tecnici e brevi snippet.
- Dati sensibili (Authorization, Cookie/Set-Cookie, token, API key, JWT, bearer, email, numeri carta, query string sensibili) vengono **sanitizzati o troncati** prima dell'invio.
- Con `--local-ai-strict-local` (attivo di default) sono ammessi solo endpoint locali/privati (`localhost`, `127.0.0.1`, `::1`, IP RFC1918): un endpoint pubblico viene bloccato con un warning non fatale.

### Opzioni del layer AI

| Opzione | Default | Descrizione |
| --- | --- | --- |
| `--local-ai` | *off* | Abilita il layer AI locale |
| `--local-ai-endpoint` | `http://localhost:11434/api/generate` | Endpoint Ollama-compatibile |
| `--local-ai-model` | `llama3.1:8b` | Modello locale da usare |
| `--local-ai-timeout` | `300` | Timeout della richiesta (secondi) |
| `--local-ai-max-entries` | `40` | Max entry HAR rilevanti inviate al modello |
| `--local-ai-output` | `auto` | Path del JSON AI (`auto` = accanto al report) |
| `--local-ai-strict-local` / `--local-ai-no-strict-local` | *on* | Consente solo endpoint locali/privati |
| `--local-ai-append-report` / `--local-ai-no-append-report` | *on* | Aggiunge la sezione AI al report HTML |
| `--local-ai-raw` | *off* | Invia anche brevi snippet di body (comunque sanitizzati) |

In caso di Ollama spento, modello non installato, endpoint non locale, timeout o JSON non valido, HARootCase continua normalmente: il report HTML viene generato e la sezione AI mostra `Local AI Review non disponibile: <motivo>` (exit code invariato).

---

## 🔁 Modalità di Analisi

La modalità viene selezionata automaticamente in base ai risultati dell'Health Score:

- **ALL_HEALTHY**
  Tutti i file risultano in buono stato; il report funge da attestazione di salute e include waterfall, performance e sicurezza.

- **STANDALONE**
  Uno o più file *DEGRADED* o *BROKEN* senza un riferimento sano; focus su errori, pattern dalla Knowledge Base e remediation.

- **DIFFERENTIAL**
  Presenza combinata di file **HEALTHY** e file problematici; viene eseguita l'analisi comparativa OK vs KO e calcolata una **Root Cause** specifica.

---

## 🧩 Architettura (alto livello)

Internamente il programma:

1. individua i file HAR (argomenti CLI, drag & drop, auto-discovery)
2. effettua il parsing in strutture tipizzate (pagine, entry, tempi, header, body snippet)
3. calcola Health Score e classifica i file
4. esegue, se possibile, l'analisi **differenziale OK vs KO**
5. applica il **Rule Engine** contro la Knowledge Base JSON
6. esegue scansione **Security & PII**
7. calcola statistiche di **Performance**
8. genera output testuale + **report HTML interattivo**

---

## 📦 Packaging & Integrazione

- **Zero dipendenze esterne:** ideale per ambienti corporate, jump host, bastion server.
- **Pronto per PyInstaller:** può essere pacchettizzato in un singolo eseguibile (includendo `har_known_issues.json`).
- **Integrazione CI/CD:** può essere invocato in pipeline per analisi automatica di HAR raccolti da test end-to-end o synthetic monitoring.

---

## 📜 Licenza

Questo progetto è rilasciato sotto licenza **MIT**. Vedi il file [LICENSE](LICENSE) per i dettagli.
