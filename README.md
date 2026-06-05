# anti-skid

stop skids from touching ur code lol

## what it does

basically hashes all ur files. if someone changes even 1 character the program goes boom and sends u a discord message telling u whos stealing ur shit. idk why ppl rip code its cringe

## install

```
pip install -e .
```

or just copy the anti_skid folder into ur project idc

## how to use

### 1. make a baseline
```
anti-skid-gen .
```
this makes manifest.json with all the hashes or whatever

### 2. slap this at the top of ur main file
```python
import anti_skid
```

thats literally it. if the code got touched it dies and dms u on discord

### 3. webhook (optional)
```
set ANTI_SKID_WEBHOOK=https://discord.com/api/webhooks/ur_webhook
```
or just export if ur not on windows. if u dont set one it just prints to console

### 4. ship it
include manifest.json with ur project. done. go outside

## what u get when someone steals ur code

- what files they touched + hash diffs
- their ip (public + local)
- their username + hostname
- if discord is running
- if theyre in a vm or docker
- open ports on their machine
- other nerd stuff

## env vars

| thing | does |
|-------|------|
| `ANTI_SKID_WEBHOOK` | discord link |
| `ANTI_SKID_MANIFEST` | custom manifest path |
| `ANTI_SKID_DISABLE` | set to 1 to skip check (dont do this) |

## requirements

python 3.8+ and literally nothing else. uses stdlib cuz i cba to pip install junk

## if ur gonna obfuscate it

pyarmor or compile to pyc. not that deep. just dont leave it raw if ur paranoid

## files

```
anti_skid/
├── anti_skid/
│   ├── __init__.py      # preflight check
│   ├── manifest.py      # hashing stuff
│   ├── integrity.py     # compares hashes
│   ├── telemetry.py     # discord sender
│   ├── environment.py   # sniffs the host
│   └── cli.py           # anti-skid-gen
├── manifest.json         # dont delete this lol
├── setup.py
└── requirements.txt
```

## license

mit. do whatever

---

*if u skid my anti-skid thats kinda ironic ngl*