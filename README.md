# phishRonin

A safe-by-default PowerShell triage toolkit for phishing investigations:
- Parse headers (SPF/DKIM/DMARC, Received chain)
- Static DOCX artifact extraction (external relationships, embedded objects, URLs)
- IOC export + hunting query generation
- Optional M365 Graph quarantine workflow (dry-run scaffold)

> **Safety**: phishRonin does *not* detonate attachments. Static analysis only.

## Quickstart

```powershell
# 1) Triage a message
.\ronin.ps1 triage -Eml .\sample.eml -DocPath .\PlaybackAudioDocs.docx -HtmlReport -OutDir .\out

# 2) Headers only
.\ronin.ps1 headers -HeadersFile .\headers.txt

# 3) DOCX inspection only
.\ronin.ps1 doc -DocPath .\PlaybackAudioDocs.docx

# 4) Export IOCs + hunting queries
.\ronin.ps1 hunt -Eml .\sample.eml -Provider MDE -OutDir .\out -Json

# 5) M365 quarantine scaffold (dry-run)
.\ronin.ps1 quarantine -Mailbox user@domain -MessageId <id> -Action MoveToJunk -DryRun
```

## Config

Edit `config/ronin.config.json`.

- `scoring.*` controls thresholds.
- `graph.*` holds tenant/app identifiers for Graph workflow.
- Keep secrets out of git (use env vars / secure storage).

## Structure

```
phishRonin/
├── ronin.ps1
├── modules/
│   ├── RoninHeaders.psm1
│   ├── RoninTriage.psm1
│   ├── RoninDoc.psm1
│   ├── RoninHunt.psm1
│   └── RoninQuarantine.psm1
├── config/
│   └── ronin.config.json
├── templates/
│   └── triage-report.html
└── README.md
```

## Next steps (recommended)
- Add robust EML/MIME parsing for attachments (System.Net.Mail is limited; consider a MIME parser).
- Implement Graph token acquisition (client secret or certificate) with minimum scopes.
- Add allow-listing and domain reputation sources (optional).
