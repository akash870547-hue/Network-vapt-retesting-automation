# Network VAPT Retest Example

The baseline and retest files are synthetic examples for demonstrating comparison.

Run:

```bash
python retest.py examples/baseline.json examples/retest.json
```

Expected classification:

- Telnet exposure: **FIXED**
- HTTP exposure: **OPEN**
- HTTPS exposure: **CHANGED**

These files do not represent a real host or real assessment.
