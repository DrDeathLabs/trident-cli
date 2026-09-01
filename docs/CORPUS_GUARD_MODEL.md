# Corpus Guard Model

The corpus calibration subsystem builds local CWE profiles and a serialized
sklearn artifact from real-world CVE data. During automatic triage, the active
corpus guard uses each qualifying profile's expected tier with deterministic
factor ceilings and floors. The model commands build and report the trained
artifact and its metadata; this document describes both pieces and how to
maintain them.

---

## Data sources

The corpus model is built from seven vulnerability intelligence feeds:

| Feed | Source | Approx. size |
|------|--------|-------------|
| NVD | National Vulnerability Database (NIST) | 286,000 CVEs |
| EPSS | Exploit Prediction Scoring System | 366,000 CVE scores |
| KEV | CISA Known Exploited Vulnerabilities | 1,600 entries |
| ExploitDB | Exploit Database (Offensive Security) | 27,000 exploits |
| CWE | Common Weakness Enumeration taxonomy | 969 weakness types |
| vulnrichment | CISA vulnrichment enrichment dataset | 177,000 records |
| OSV | Open Source Vulnerabilities database | 32,000 OSS advisories |

These feeds are joined on CVE ID and CWE ID to produce a unified dataset with enriched labels. EPSS scores, KEV membership, and ExploitDB entries are used as training signals for exploitability ground truth.

---

## CWE profiles

After joining the feeds, the model groups CVEs by CWE and computes a statistical profile for each CWE with at least 200 CVEs:

- Median CVSS base score
- 25th, 75th, 85th, 95th percentile CVSS scores
- Empirical distribution of CVSS attack vector labels
- Empirical distribution of CVSS impact labels
- KEV rate (fraction of CVEs in the KEV catalog)
- ExploitDB rate (fraction with a public exploit)

These profiles represent what severity ratings actually look like for vulnerabilities of each type, across real-world disclosure data.

**766 CWE profiles** meet the 200-CVE threshold as of the default corpus build. CWEs with fewer than 200 CVEs are excluded from calibration - the corpus guard skips those findings.

---

## Trained model artifact

The refresh pipeline also trains a gradient-boosted classification model
(`sklearn.ensemble.GradientBoostingClassifier`) on the CWE profiles:

**Input features** (per finding):
- Finding's CWE ID
- CWE profile percentiles for the CWE
- Council-assigned impact label (encoded)
- Council-assigned attack vector label (encoded)
- Tool confidence score

**Output:**
- Calibrated severity class (`critical`, `high`, `medium`, `low`)
- Calibrated attack vector class (`remote_unauth`, `remote_auth`, `adjacent`, `local`)

The artifact is trained and serialized by `model refresh`, `model build`, or
`model train`, and its metadata is exposed by `model info`. Ordinary triage does
not load this classifier to make a live prediction. The active corpus guard
reads the local profile's `expected_tier`, then applies deterministic factor
ceilings or floors. Guard evaluation makes no external API requests.

---

## Model commands

### Build the corpus (download feeds)

```bash
trident model refresh
```

Downloads all seven feeds, joins them, computes CWE profiles, trains the gradient-boosted model, and serializes it to the local model store. This is a long-running operation - expect 20-45 minutes depending on your connection speed and hardware.

The model refresh requires an active internet connection and sufficient disk space (~2 GB for the raw feeds, ~50 MB for the compiled model).

### Check model status

```bash
trident model status
```

Displays the current model state:

```
Corpus guard model
  Status         : active
  Build date     : 2026-08-15T09:22:31Z
  CVEs indexed   : 285,847
  CWE profiles   : 766
  EPSS scores    : 366,102
  KEV entries    : 1,612
  ExploitDB      : 27,341
  Model size     : 48.2 MB
```

If `Status: missing`, the local corpus calibration state is unavailable and all
`corpus_guard` fields will be `null`.

### Train from existing data

```bash
trident model train
```

Retrains the gradient-boosted model from the existing CWE profiles without
re-downloading feeds. Use `trident model build` when the profiles themselves
also need to be rebuilt from already downloaded feed data.

### Reset the model

```bash
trident model reset
```

Deletes the corpus model and all cached feed data. After a reset, run `trident model refresh` to rebuild from scratch.

---

## When to rebuild

| Situation | Recommended action |
|-----------|------------------|
| First install | `trident model refresh` |
| Monthly maintenance | `trident model refresh` |
| KEV catalog updated (frequently) | `trident model refresh` |
| Profiles are present but `corpus_guard` is always null | Check the CWE profile threshold and the finding's current versus expected tier |
| Disk constraints, want to re-use existing feeds | `trident model build` or `trident model train` |
| Model is corrupt or giving unexpected results | `trident model reset && trident model refresh` |

The NVD, EPSS, and OSV feeds are updated frequently. Running `trident model refresh` monthly keeps the corpus current with new CVEs, updated CVSS scores, and KEV additions.

---

## Corpus guard behavior without corpus profiles

If the corpus profiles have not been built:

- The corpus guard is silently skipped for all findings
- `corpus_guard` fields will be `null` on every finding
- The class guard and reachability guard still operate normally
- Scan output is valid and usable - just uncalibrated by the corpus

Run `trident model status` to confirm whether the model is active before a production scan.

---

## Storage location

The model and feed data are stored under the directory selected by
`CALIBRATION_DATA_DIR`. The runtime default is platform-dependent and should
not be assumed in automation; `trident model path` prints the active location.

Set `CALIBRATION_DATA_DIR` to choose a writable location for the database,
feed cache, and trained model:

```bash
CALIBRATION_DATA_DIR=/mnt/fast-disk/trident trident model refresh
```

---

## See also

- [GUARDS](GUARDS.md) - how the corpus guard adjusts triage ratings
- [CONFIGURATION](CONFIGURATION.md) - `TRIDENT_DATA_DIR` and model-related config keys
- [INSTALLATION](INSTALLATION.md) - `trident install-tools --warmup` for initial setup
