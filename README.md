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
    "type": "analysis"
}
```

While `sample` type is self explanatory, the `analysis` type might be a bit more complicated. The `analysis` task is an output from
one of sandboxes: `drakvuf-sandbox`, `cuckoo`, or `joesandbox`. Analysis is a `sample` with additional memory dumps
attached.

The `analysis` type task is expected to be in format:
```
task = Task(
    headers={"type": "analysis"}
    payload={
        "sample": <sample>,
        "dumps.zip": Resource.from_directory("dumps.zip", dumps_path.as_posix()),
        "dumps_metadata": [
            {"filename": <dump1_filename>, "base_address": <dump1_base_address>},
            {"filename": <dump2_filename>, "base_address": <dump2_base_address>},
            {"filename": <dump3_filename>, "base_address": <dump3_base_address>},
            [...]
        ],
    }
)
```
where `dumps_metadata` contains information about filename and base address of every memory dump in `dumps.zip`. The
following attributes are:
- `filename` - a relative path to dump in the dumps.zip archive;
- `base_address` - hex-encoded dump base address (leading `0x` is supported);
You can specify multiple entries for the same file if the same memory dump was found on different base addresses.

For the analysis type, yaramatcher runs rules against all dumps described in `dumps_metadata` payload. It then appends result tags to the parent sample.

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

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
