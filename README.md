# YaraMatcher karton service

Scans analyses and samples with yara rules and spawns tasks with appropiate tags.

**Author**: CERT.pl

**Maintainers**: msm, nazywam

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
}, {
    "type": "analysis",
    "kind": "joesandbox"
}
```

**Produces:**
```json
{
    "type": "sample",
    "stage": "analyzed"
}
```

## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Then install karton-yaramatcher from PyPi:

```shell
$ pip install karton-yaramatcher
```

And run the karton service by pointing it to your [YARA](https://virustotal.github.io/yara/) rules repository:

```shell
$ karton-yaramatcher --rules yara_rule_directory
```
or if your yara rules are in your Karton S3 storage (MinIO)
```shell
$ karton-yaramatcher --bucket yara_rule_bucket
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
