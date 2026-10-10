db/
├── hikvision.yaml
├── dahua.yaml
├── axis.yaml
├── uniview.yaml
├── foscam.yaml
├── reolink.yaml
├── amcrest.yaml
├── _generic.yaml      ← shared patterns (ONVIF, RTSP, generic MJPEG)
└── README.md          ← how to add a new brand

Rules

* One brand — one file. It does not matter whether the file contains 5 models or 5000. The filename is simply the brand name.
* A file may be empty. If a brand exists but no models have been collected yet, the file serves as a signal: “nothing here yet.”
* `_generic.yaml` is the only shared file. It holds patterns that apply to entire standards (ONVIF, RTSP, generic MJPEG).
* The leading underscore (`_generic.yaml`) ensures that sorting in `ls` or Finder puts it at the top as a system file.

README.md (example content)
markdown

```
# URL Pattern Database

One file per brand. Filename = brand name (lowercase).
Special files start with `_` and are not brands:
- `_generic.yaml` — shared patterns (ONVIF, RTSP, generic MJPEG)

## How to add a new brand
1. Create `db/<brand>.yaml`
2. Structure:
   ```yaml
   <brand>:
     <model>:
       stream: ["rtsp://..."]
       snapshot: ["http://..."]
```

3. If a brand has more than 20 models, use prefix matching:
yaml

```
DS-2CD:
  stream: ["rtsp://{user}:{pass}@{ip}:554/Streaming/Channels/101"]
```

text

```

---

## Prompt for your agent (English)

> **Task:** Split the current single `db/url_patterns.yaml` into per-brand files under `db/`. Follow the structure and rules below exactly.
>
> **Structure:**
> ```
> db/
> ├── hikvision.yaml
├── dahua.yaml
├── axis.yaml
├── uniview.yaml
├── foscam.yaml
├── reolink.yaml
├── amcrest.yaml
├── _generic.yaml
└── README.md
```
>
> **Rules:**
> - One brand — one file.
> - A file may be empty.
> - `_generic.yaml` is the only shared file.
> - The leading underscore makes it sort first.
>
> **Actions:**
> 1. Create `db/` if it doesn't exist.
> 2. Read the existing `db/url_patterns.yaml`.
> 3. For each top‑level key (brand), write a separate `<brand>.yaml` containing only that brand's data.
> 4. Move the `generic` section into `_generic.yaml`.
> 5. Keep the original file as `db/url_patterns.yaml.bak` (do not delete).
> 6. Update `scanner.py` so `_load_url_patterns()` loads all `*.yaml` from `db/` and merges them into a single dictionary.
> 7. Add `db/README.md` with the rules above.
> 8. Test that the scanner still loads all patterns correctly (print the number of brands and models).
>
> **Reply in Russian** (explanations), but keep code, filenames, and commands in English.
