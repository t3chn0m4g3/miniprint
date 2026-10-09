# Validierung der Phasen 2–6

Stand: 2026-10-09. Lokal geprüft, noch nicht veröffentlicht.

## Automatisierte Prüfungen

| Prüfung | Ergebnis |
|---|---|
| `UV_CACHE_DIR=/private/tmp/miniprint-uv-cache uv run --no-sync pytest -q` | 90 passed, 3 skipped, 2 subtests passed |
| `uv run --no-sync ruff check .` | All checks passed |
| Opt-in-Container-Smoke (`MINIPRINT_CONTAINER_SMOKE=1`) | 3 passed |
| ewsposter: `python -m unittest discover tests` | 14 tests, OK |

Die drei regulären Skips sind dieselben Opt-in-Smoke-Tests; sie wurden separat
gegen das gebaute Image `miniprint:lure2026` ausgeführt. Der Container verwendete
read-only Root-FS, UID/GID 2000, cap_drop ALL, no-new-privileges, CPU-/Speicher-/PID-
und Dateideskriptorlimits entsprechend Compose sowie beschreibbare Test-Volumes.
Die Smoke-Tests prüfen außerdem HTTP/1.1, genau einen Server-Header, CSV/Login/
LDAP-Kette, Secret-Redaktion und bytegenaue Erfassung eines 500-KB-PostScript-Jobs.

## Zusätzliche Container-Prüfungen

- Brother, HP und Lexmark: identische Herstellerinformationen über HTTP und PJL.
- HP/Lexmark: gespeicherte Identität bleibt nach Container-Neustart unverändert.
  Random-Auswahl und Reroll sind zusätzlich mit temporären State-Verzeichnissen
  in den Unit-Tests abgedeckt.
- PRET: `id`, `info config`, `env`, `ls`, `put`, `reconnect`, `ls` erfolgreich.
  Die hochgeladene 20-Byte-Datei erscheint nach Reconnect weiterhin. PRET benötigt
  unter Python 3 eine lokale Bytes/str-Anpassung in `pjl.put`; diese Änderung
  wurde ausschließlich im temporären PRET-Checkout vorgenommen.
- 200 Idle-HTTP-Verbindungen: gemeinsame Slots begrenzen Handler; danach
  beantwortet der Container wieder OPTIONS. Negative Content-Length wird als
  leerer Body verarbeitet; der leere Login erhält 401. Healthcheck bleibt gesund.
- Nichtnumerisches FORMLINES über Linux-Loopback 127.0.0.2: diese Quelle erhält
  auf HTTP und PJL keine Antworten. Quelle 127.0.0.3 erhält weiterhin Brother-ID.
- Der Brother-Passwortalgorithmus wurde unabhängig mit der offiziellen
  Metasploit-Ruby-Routine überprüft; beide unmaskierten Testvektoren stimmen.

## nmap: Ergebnis und Grenze

Nmap 7.991 erkennt den Brother-HTTP-Banner als Debut embedded httpd 1.30.
Die isolierte, unveränderte offizielle `hp-pjl`-Probe erkennt
`Brother MFC-L9570CDW` auf dem abweichenden lokalen PJL-Testport.
Dafür wurde `--versiondb` mit einer Datei aus NULL- und hp-pjl-Probe der lokal
installierten nmap-Datenbank verwendet. Auch der vollständige Scan mit
`nmap -sV --version-all -Pn -p 57950 127.0.0.1` erkennt nach 274,66 s
`hp-pjl Brother MFC-L9570CDW`. Die normale PJL-Probe hat rarity 9 und
wird bei `--version-light` auf einem zufälligen Host-Port nicht ausgewählt.

HP und Lexmark liefern ihre erwarteten Banner und Modellnamen; nmap
`--version-light` erkennt die HTTP-Antworten dieser Profile in dieser Datenbank
nicht eindeutig. Eine automatische nmap-Herstellerzuordnung für alle drei
Profile ist daher **nicht nachgewiesen**. Dies ist eine Grenze der Validierung;
die Profile sind eine Näherung und keine vollständige Firmware-Emulation.

## ewsposter: echte Logs, zwei Offline-Läufe

`ews.py -c <Test-Konfigurationsverzeichnis> -m miniprint -E` wurde über zwei
separate Prozesse ausgeführt. Der erste Logausschnitt endet innerhalb der
PostScript-Session, der zweite enthält das vollständige Log. `-E` schreibt nur
lokale EWS-Spooldateien. Interne/externe IP-Adressen waren fest konfiguriert;
HPFeeds, InfluxDB und Netzwerkversand waren deaktiviert.

Da macOS keine abstrakten Linux-UNIX-Sockets unterstützt, ersetzt ein temporärer
Prüfwrapper ausschließlich `modules.einit.locksocket` durch einen lokalen UDP-
Socket. Gegenseitiger Prozess-Ausschluss ist damit nicht geprüft. Entry point, Konfigurationsinitialisierung, Adapter, EAlert, Indexdateien,
XML-Erzeugung und Spoolverarbeitung laufen unverändert. Dies ist kein nativer
Linux-Test des ewsposter-Prozesslocks.

Ergebnis: **344 Alerts / 344 eindeutige Session-IDs**,
jede ID genau einmal. Die aufgeteilte Session `f1248666-e923-400c-a7a0-5e1d8e048a72` erscheint
nur nach ihrem Abschluss im zweiten Lauf. **24 Artefakte** sind als binary/largepayload
angehängt; Zielports sind **80 und 9100**; **4 echte leere PJL-Sessions** erzeugen
keinen Alert. Artefakt-Priorität und Zusammenfassung aller Artefakte sind
zusätzlich durch Regressionstests abgedeckt. Identische Payload-Hashes werden
vom bestehenden EAlert-Malwareindex dedupliziert.

Der erweiterte Replay reproduzierte XML-Abbrüche durch Steuerzeichen in
Request-Texten. Ein zusätzlicher Regressionstest schlägt vor dem Fix fehl und
besteht danach; der Adapter bereinigt diese Texte, Binärartefakte bleiben exakt.

Echte, unveränderte Beispielzeilen stehen in [miniprint-sample.jsonl](miniprint-sample.jsonl).
Die temporären Rohlogs, Spooldateien, PRET-Ausgabe und Testergebnisse liegen in
`/private/tmp/miniprint-verify-96e7cf7c`. Frühere Smoke-Artefakte wurden durch den Test aufgeräumt und können
beim Replay als fehlend gemeldet werden; neue Replay-Artefakte bleiben vorhanden.

## Veröffentlichung

Alle Änderungen sind lokal committet. Die aktualisierte PR-Beschreibung ist in
[ewsposter-pr18-body.md](../ewsposter-pr18-body.md) vorbereitet. Für beide Pushes und die Aktualisierung von PR #18 ist eine ausdrückliche Zustimmung erforderlich.
