# YaraMatcher karton service

Scans analyses and samples with yara rules and spawns tasks with appropiate tags.

Author: CERT.pl
Maintainers: msm, nazywam

**Consumes:**
```json
{
    "type": "sample",
    "stage": "recognized",
    "kind": "runnable"
}, {
    "type": "sample",
    "stage": "recognized",
    "kind": "dump"
}, {
    "type": "analysis",
    "kind": "cuckoo1"
}, {
    "type": "analysis",
    "kind": "drakrun"
}
```

**Produces:**
```json
{
    "type": "sample",
    "stage": "analyzed"
}
```
