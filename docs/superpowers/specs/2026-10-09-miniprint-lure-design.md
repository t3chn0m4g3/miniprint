# miniprint `next`: Review-Ergebnisse und Umbau zum glaubwürdigen Köder 2026

## Context
Commit `d98c021` auf `next` (feat!: modernize and harden miniprint) wurde mit /code-review, /security-review und einem
Brainstorming geprüft. Das Brainstorming ging der Frage nach, ob die Änderungen reichen, um 2026 Angreifer anzulocken.
Ergebnis: Die Härtung ist solide, das Security-Review fand keinen Befund ≥ 8. Als Köder reicht es aber **nicht**:
gängige Druckjobs gehen verloren, und Persona sowie Protokolle lassen sich trivial fingerprinten. Die wertvollste aktuelle Köderkette
(Brother/Rapid7 2025) ist nur angedeutet.
Entscheidung des Nutzers: **voller Umfang inklusive Brother-Kette**, Persona **konfigurierbar** (Brother/HP/Lexmark).

### Review-Ergebnisse (Kurzform)
**Security-Review:** keine Befunde. Upload-Namen kommen aus Hash und Zeitstempel, das FS ist rein pyfakefs, Ausgaben sind escaped, Logs json-sicher.
**Code-Review:**
1. `web_admin.py:113`: negativer Content-Length führt zu `read(-1)` und damit zum OOM.
2. `web_admin.py:69`: kein HTTP-Timeout und kein Connection-Cap, dadurch wird `pids_limit` erschöpft und PJL fällt aus.
3. `server.py:307`: Das globale try/except fehlt, Exceptions beenden die Session mit einem Nicht-JSON-Traceback.
4. `printer.py:493`: FSUPLOAD im Textmodus führt bei Binärdaten zu einem UnicodeDecodeError, außerdem stimmt SIZE nicht.
5. `server.py:246`: Das 64-KiB-Gesamtlimit macht das 1-MiB-Job-Limit wirkungslos.
6. `server.py:383`: Der Body nach `@PJL ENTER LANGUAGE=` wird verworfen, gängige Druckjobs gehen verloren.
7. `server.py:199`: Ohne Gesamtdeadline können Slow-Clients alle 16 Slots belegen.
8. `web_admin.py:261`: doppelter `Server`-Header.
9. `web_admin.py:16` gegenüber `printer.py:36`: HTTP zeigt Brother, PJL und fake-FS zeigen HP.
10. `printer.py:174`: Bei bloßem LF ist der Payload leer, und Parameter im Payload überschreiben NAME.
Weitere Punkte: uid 1000 gegenüber den T-Pot-Volumes, doppelte Helfer, ein unbenutzter `connection_lock`, der Healthcheck ignoriert `--no-http`.

**Brainstorming, zusätzliche Fingerprints:** `ONLINE=True` (Python-Bool), ECHO/INFO enden auf `\x1b` statt `\r\n\x0c`,
HTTP/1.0 und Python-Fehlerseiten (501/400), FS und RDYMSG werden pro Verbindung zurückgesetzt, Seriennummer und Hostname sind im öffentlichen Repo hartkodiert,
die CVE-Hints mischen Lexmark (CVE-2025-1127, -9269), Ricoh (CVE-2025-65079..81) und Brother. Es fehlen PRET-Kernbefehle,
`/etc/mnt_info.csv` (CVE-2024-51977), ein funktionierender Login mit Default-Passwort (CVE-2024-51978) und `SET FORMLINES` (CVE-2024-51982).

## Vorgehen
Den Abschnitt „Design“ dieses Plans als Spec unter `docs/superpowers/specs/2026-10-09-miniprint-lure-design.md` committen,
danach in sechs Phasen umsetzen (Phase 6 betrifft das Repo ewsposter). Jede Phase mit TDD, eigenem Commit und grünem `uv run pytest`.
Branch: lokaler Feature-Branch `lure-2026` von `next`. Push nach `origin` (t3chn0m4g3/miniprint) erst nach Rückfrage.

### Phase 1: Robustheit (CR 1–4, 7, 10 und Nebenbefunde)
- `web_admin.py`: `content_length = max(0, …)`. Handler-`timeout` (z. B. 15 s). Ein gemeinsames Verbindungslimit für HTTP
  (BoundedSemaphore wie bei `LimitedThreadingTCPServer` in `server.py:130`, nicht blockierend, sonst Close und Log `connection_limit`).
- `server.py:_process_data`: `try/except Exception` um jedes `_process_command` mit einem strukturierten Event `command_error`
  (Exception-Typ, Hash und Preview), die Session bleibt offen.
- Gesamtdeadline pro Session über das neue Flag `--session-timeout` (Default 300 s), die Prüfung läuft in `_handle_loop`.
- `printer.py`: FSUPLOAD liest binär. Die Kommando-Antworten werden zu `bytes` (die `_response`-Grenze arbeitet auf Bytes),
  damit Inhalt und `SIZE` übereinstimmen. `_split_file_payload` trennt an `\r\n` **oder** `\n`. Parameter werden nur aus dem Header gelesen.
- Dedupe: `ContextLoggerAdapter`/`format_utc` in ein neues `telemetry.py` auslagern, `connection_lock` und `/tmp/miniprint` entfernen.
- Dockerfile: Die UID wird zum `ARG` (Default auf die T-Pot-Konvention abstimmen, vorher in der tpotce-Compose prüfen). Der Healthcheck respektiert `--no-http`.

### Phase 2: Payload-Capture (CR 5, 6)
- Einen zustandsbehafteten Stream-Parser in `server.py`/`printer.py` einführen. `@PJL ENTER LANGUAGE=<L>` schaltet in den Job-Modus.
  Alles bis zum nächsten UEL `\x1b%-12345X` (auch über Chunk-Grenzen, Tail-Puffer von 9 Bytes) oder bis EOF wird als Artefakt gespeichert,
  mit Suffix je Sprache (`.ps`, `.pcl`, `.pdf`, `.prn`) und `language` im Log. Ein `%!` am Chunk-Anfang bleibt als Sonderfall erhalten.
- Limits entkoppeln: `max_request_bytes` zählt nur Bytes im PJL-Kommandomodus, Job-Bytes zählen gegen `max_job_bytes`.
  Das harte Verbindungslimit ist die Summe aus beiden.
- Unbekannte PJL-Kommandos werden mit Name, Hash und Preview geloggt (Level info statt debug), damit neue Angriffsmuster sichtbar bleiben.
- Bestehende Helfer weiterverwenden: `Printer._save_artifact`, `_artifact_name`, `payload_hash/preview`.

### Phase 3: Konfigurierbare Persona und Fingerprint-Entfernung (CR 8, 9)
- Neues Modul `personas.py`: ein Dataclass `Persona` mit vendor, model, PJL-ID, INFO-Texten (CONFIG, VARIABLES, FILESYS, MEMORY,
  PAGECOUNT, PRODINFO), Seriennummern-Generator, Server-Banner, HTTP-Routen und Templates, CVE-Hint-Mapping und dem Pfad
  `fake-files/<persona>/` mit Seed-FS. Profile `brother` (Default), `hp` (die bestehenden fake-files ziehen nach `fake-files/hp/`) und `lexmark`.
  Banner, Pfade und Seitentitel stammen aus öffentlichen Quellen (nmap-service-probes, Nuclei-Templates, Rapid7-Writeup) und werden im Modul als Quelle kommentiert.
- Persona-Wahl beim Start: `--persona {brother,hp,lexmark,random}` (Default `random`), zusätzlich die Umgebungsvariable
  `MINIPRINT_PERSONA` für Compose/T-Pot (das CLI-Flag hat Vorrang).
  - Fest gewählt: genau diese Persona wird verwendet. Weicht sie von der gespeicherten Identität ab, wird eine neue Identität für diese Persona erzeugt.
  - `random`: Beim ersten Start wird eine Persona per `secrets.choice` ausgewählt und **mit der Identität gespeichert**.
    Spätere Starts übernehmen sie. Ein Vendor-Wechsel bei jedem Restart wäre in der Shodan- oder Censys-Historie selbst ein Fingerprint.
    Neu würfeln: `data/identity.json` löschen oder `--reroll-identity` setzen.
  - Die gewählte Persona geht ins Konsolen-Log (`server_start`, Feld `persona`) und als Feld `persona` in jedes Session-Event.
- `--state-dir` (Default `data/`, neues Compose-Volume `./data/:/app/data/`). Die Identität (Persona, Seriennummer im Vendor-Format,
  Hostname, MAC-Suffix, Firmware aus einer Liste plausibler Versionen) wird beim ersten Start zufällig erzeugt und in
  `data/identity.json` gespeichert. Damit unterscheidet sich jede Installation, bleibt aber über Restarts stabil. Ist das State-Dir nicht beschreibbar,
  wird die Identität nur im Speicher gehalten, und es erscheint eine Warnung im Konsolen-Log.
- PJL: Antwortformat korrigieren (`\r\n\x0c`, `ONLINE=TRUE`). Neu: die INFO-Familie, `INQUIRE`/`DINQUIRE`/`SET`/`DEFAULT`
  (Variablen-Store pro Gerät), `JOB`/`EOJ` und `RNVRAM` (feste Pseudo-Bytes und Log). Die Dispatch-Tabelle in `server.py:357-388` wird zu einem dict.
- Geräte-Zustand: ein neuer `DeviceStateStore` (LRU über src_ip, max. 256 Einträge, TTL 24 h, Lock) hält FS, Variablen und RDYMSG
  über Reconnects hinweg. FSINIT setzt nur den Eintrag dieser IP zurück. Der Eintrag ersetzt das `Printer(...)` pro Verbindung in `server.py:200`.
- HTTP: `version_string()` überschreiben (genau ein Server-Header), `protocol_version = "HTTP/1.1"`, `send_error` und
  `error_message_format` persona-spezifisch. `OPTIONS`/`DELETE`/`PATCH` bekommen persona-typische Antworten. Pfade, Klassifizierung und CVE-Hints kommen aus der Persona
  (z. B. CVE-2025-1127 und -9269 nur bei `lexmark`, die WSD-CVEs 51980/81 nicht mehr an URL-Parameter hängen).

### Phase 4: Brother-Köderkette (nur Persona `brother`, also auch wenn `random` auf brother fällt)
- `GET /etc/mnt_info.csv` liefert eine CSV mit Modell, Seriennummer und Node-Name aus `identity.json`. Event `serial_leak_probe`, Hint CVE-2024-51977.
- Default-Passwort: Rapid7s veröffentlichten Ableitungsalgorithmus (Seriennummer → Passwort) als `brother_default_password(serial)`
  portieren, mit den Testvektoren aus dem Writeup bzw. dem Metasploit-Modul. Der Login mit `admin`/abgeleitetem Passwort gelingt: Event
  `default_password_success` (CVE-2024-51978), es wird ein Session-Cookie (uuid4, im Speicher, TTL) gesetzt. Alle anderen Logins schlagen wie bisher fehl.
- Fake-Admin-Bereich hinter dem Cookie: Seiten für Netzwerk, LDAP, SMTP, SNMP und Firmware. POSTs werden geloggt (Felder gekürzt, Passwörter
  nur als `secret_supplied`) und als „gespeichert“ quittiert. Änderungen an LDAP- oder SMTP-Server liefern Event `passback_attempt` (CVE-2024-51984).
  Ein Firmware-Upload wird als Artefakt gespeichert (Hash und Größenlimit). **Es gibt keine ausgehenden Verbindungen.**
- PJL: `@PJL SET FORMLINES=<nicht numerisch>` erzeugt Event `pjl_crash_probe` (CVE-2024-51982). Danach wird die Verbindung geschlossen und diese src_ip
  bekommt 60–120 s lang keine Antwort, als simulierter Reboot. Das gilt nur pro IP, damit kein Selbst-DoS entsteht.

### Log-Schema-Vertrag (gilt für alle Phasen und für den ewsposter)
Jede Änderung am JSONL-Format wird hier festgehalten und in `README.md` als Abschnitt „Log schema“ dokumentiert:
- **Sessionende:** Jede Session endet mit genau **einer** Zeile mit `session_end`. Bei PJL sind das `connection_closed`, `empty_connection` und `connection_limit`.
  Bei HTTP gibt es neu ein Event `http_request_completed` pro Request ohne `session_end`, und `http_connection_closed` mit `session_end` wird einmal in
  `finish()` geschrieben. Das ist für Keep-Alive unter HTTP/1.1 nötig, bisher kam „close_conn“ pro Request. Auch bei `command_error` und einem Abbruch
  durch die Gesamtdeadline wird `session_end` garantiert (`finally`).
- **Feldnamen:** Pfade im virtuellen FS heißen einheitlich `virtual_path` (bisher `file_name`, `dir`, `upload_file`, `item`).
  `file_name` bezeichnet nur noch Artefakte in `uploads/`. Neu kommen `artifact_type` (`ps|pcl|pdf|raw|firmware`), `language`, `persona` (in jeder Zeile)
  und `cve_hint` hinzu. Das ist auch bei PJL eine kommagetrennte Liste.
- **Ports:** HTTP lauscht im Container direkt auf **80** statt auf 8080, Compose bildet `80:80` ab. Docker erlaubt Nicht-Root-Bind auf
  Ports unter 1024 über `net.ipv4.ip_unprivileged_port_start=0`, das ist ab Docker 20.10 Standard und wird vorab verifiziert, sonst kommt `sysctls` in Compose.
  Damit stimmt `dest_port` im Log mit dem exponierten Port überein. Bisher meldete der ewsposter 8080.

### Phase 6: ewsposter PR #18 (telekom-security/ewsposter, Branch `miniprint`, dein PR)
Review-Befunde zu `honeypots/miniprint.py` im PR:
1. **Sessions werden über ewsposter-Läufe hinweg zerrissen** (`miniprint()`, Zeilen 228-246). `lineREAD` merkt sich den Zeilenzähler zwischen
   Läufen (`a.loop`). Offene Sessions werden am Ende jedes Laufs trotzdem als Alert verschickt, und der Rest derselben Session landet im nächsten Lauf als
   zweiter, unvollständiger Alert mit gleicher `session_id`. Fix: Alerts nur für Sessions mit `session_end` verschicken. Für offene Sessions wird
   der Zähler per `alertCount(MODUL, "set_counter", setto=<erste Zeile der ältesten offenen Session>)` zurückgesetzt. Versendete IDs kommen in
   `fileIndex("miniprint.session")` (wie bei cowrie und adbhoney), beim erneuten Einlesen werden sie übersprungen. Eine Session ohne Ende, die älter als 10 min ist, wird
   trotzdem versendet (Absicherung gegen Abstürze).
2. **`size`/`limit` mischen Bedeutungen** (Zeilen 108-115, last-write-wins aus Append-, Artefakt- und Limit-Events). Fix: getrennte Felder
   `artifact_size`, `request_too_large_size`, `limit_event` usw.
3. **`file_name` mischt Artefakte und virtuelle FS-Pfade** (`LIST_FIELDS` und Zeile 120). Wird mit `virtual_path` aus dem Schema-Vertrag aufgelöst.
   Neues Listenfeld `virtual_path`, Artefakte nur aus Events `save_*` (`file_name` + `payload_sha256`).
4. **Nur das erste Artefakt pro Session wird gesendet** (`break` in `_add_artifact`), weitere gehen dauerhaft verloren. Fix: das wertvollste
   Artefakt auswählen (Priorität `firmware > ps/pcl/pdf > raw`, dann die Größe). Alle Artefakte erscheinen als `artifacts`-Liste (Name:sha256) in adata.
5. **HTTP-Request-Zusammenfassung** nimmt nur die erste Methode und URL (Zeilen 197-206). Fix: `request` als Liste `"METHOD URL"` (Zeilenumbruch als Trenner).
   Das passt zu Keep-Alive.
6. **`secret_supplied`** übernimmt nur den ersten Wert. Fix: true, sobald irgendeine Zeile true enthält.
7. **Leere Verbindungen** (`empty_connection`) erzeugen jetzt Alerts, der alte Code tat das nicht (er erzeugte Alerts nur bei Daten). Ich schlage vor, sie per Default zu überspringen
   und die neue Option `send_empty_connections = false` in `[MINIPRINT]` einzuführen. So steigt das Alert-Volumen durch Portscans nicht sprunghaft.
8. **Neue Felder und Events aus Phase 1-4 durchreichen:** `persona`, `language`, `artifact_type`, `cve_hint` (Union über die Session),
   Events `default_password_success`, `passback_attempt`, `pjl_crash_probe`, `serial_leak_probe` und `command_error` als `event`-Liste.
- Tests in `tests/test_miniprint.py` je Befund ergänzen (FakeEAlert um `alertCount`/`fileIndex` erweitern). Die Beispiel-Logs in der PR-Beschreibung
  werden mit echten Zeilen aus dem neuen Container ersetzt.
- Arbeitsort: einen Clone unter `/Users/A3918320/Documents/Claude/ewsposter` anlegen, Branch `miniprint` auschecken und lokal committen. **Push auf den PR-Branch
  und das Update der PR-Beschreibung erst nach Rückfrage.**
- Reihenfolge: Phase 6 kommt **nach** Phase 1-4, damit der ewsposter gegen das finale Schema getestet wird. Den Schema-Vertrag oben
  legen wir aber vorher fest. Für die End-to-End-Prüfung wird eine echte `miniprint.json` aus dem Smoke-Lauf durch den ewsposter geschickt
  (`ews.py` mit lokalem `ews.cfg`, Ausgabe ohne Senden bzw. JSON-Spool prüfen).

### Phase 5: Doku und Tests
- README: Personas, State-Dir, neue Events und CVE-Mapping, Breaking Changes. Die Container-Smoke-Tests um Persona- und Brother-Kette erweitern.

## Kritische Dateien
`server.py`, `printer.py`, `web_admin.py`, neu `personas.py`, `telemetry.py`, `device_state.py`, `fake-files/<persona>/`,
`Dockerfile`, `docker-compose.yml`, `tests/test_{server,printer,web_admin}.py`, neu `tests/test_personas.py`, `tests/test_brother_chain.py`.
ewsposter: `honeypots/miniprint.py`, `tests/test_miniprint.py`, `ews.cfg.default`, `ews.cfg.docker` (Option `send_empty_connections`).

## Außerhalb des Scopes
SNMP (161/udp), LPD (515), WSD (3702), IPP (631, bewusst IPPHoney überlassen). Das wäre ein eigener Spec.

## Verification
- `uv run pytest` grün nach jeder Phase. Neue Tests für jeden Code-Review-Befund (Regressionstest zuerst, TDD).
- Manuell gegen `docker compose up -d --build`:
  - `printf '\x1b%%-12345X@PJL JOB\r\n@PJL ENTER LANGUAGE=POSTSCRIPT\r\n%%!PS\n...%%%%EOF\x1b%%-12345X' | nc host 9100` legt eine `.ps`-Datei in `uploads/` ab, auch bei 500 KB.
  - PRET (`pret.py host pjl`): `id`, `info config`, `env`, `ls`, `put`, Reconnect, `ls` zeigt die Datei weiterhin.
  - `curl -i http://host/` liefert einen Server-Header und HTTP/1.1. `curl -X OPTIONS` zeigt keine Python-Fehlerseite.
  - Brother-Kette: `curl /etc/mnt_info.csv`, Passwort lokal mit `brother_default_password` berechnen, Login per POST, Admin-POST mit LDAP-Server.
    Die erwarteten Events stehen in `log/miniprint.json`.
  - `nmap -sV -p 80,9100` erkennt bei jeder Persona einen konsistenten Hersteller auf beiden Ports.
  - Persona-Wahl: `--persona hp` liefert HP auf allen Ports. Ohne Flag wird beim ersten Start gewürfelt, nach einem Restart bleibt dieselbe Persona,
    nach `--reroll-identity` gibt es eine neue Seriennummer und ggf. einen anderen Vendor. Unit-Tests decken das mit temporärem State-Dir und gemocktem `secrets.choice` ab.
  - Robustheit: `Content-Length: -1`, 200 Idle-HTTP-Sockets und `FSMKDIR` unter einer Datei. Der Container läuft weiter, die Fehler werden als JSON geloggt.
- `RUN_CONTAINER_SMOKE=1 uv run pytest tests/test_container_smoke.py` (bzw. die dort dokumentierte Opt-in-Variable).
- ewsposter: `python -m unittest discover tests` im ewsposter-Clone ist grün. Ein Replay der echten `miniprint.json` aus dem Smoke-Lauf geht in zwei
  Hälften durch zwei ewsposter-Läufe, und es entsteht genau ein Alert pro Session mit den richtigen Feldern (`dest_port` 80/9100, Artefakt angehängt,
  keine Alerts für leere Verbindungen).
