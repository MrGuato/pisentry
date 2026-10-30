# README demos

The GIFs in the README are recordings of real runs, regenerated with:

```bash
pip install pyte pillow      # plus Docker, tmux and ffmpeg on the host
make demo
```

| File | What it does |
|---|---|
| `Dockerfile` | The throwaway demo host: `python:3-slim` plus `jq`. The agent binary is mounted in. |
| `host-setup.sh` | Makes the container look like a fresh, careless Pi: password SSH, root login, a `pi` account with a password. |
| `config.json` | Agent config with file-mode logs and 2s detector intervals so the demo is short. |
| `attack.sh` | Harmless stand-ins for eight categories, the same ones as `scripts/sim-container/sim.sh`, with narration. Documentation IP ranges only; the "miner" is a renamed `sleep`; the reverse shell connects to the container itself. |
| `stream.jq` | Prints each JSON event as one colored line. This is what the bottom pane of the live demo pipes through. |
| `rules-local.json` | The local rule pushed in the hot-reload demo. |
| `record.py` | Starts a fresh container per scene, drives an interactive shell through a pseudo-terminal (inside tmux for the split-pane scene), types the commands and saves what the terminal printed, with timing, as asciicast v2. |
| `render.py` | Emulates the terminal with pyte, draws frames with Pillow and builds the GIF with ffmpeg. |

Nothing in the output is edited. Two cosmetic steps happen at render time: pauses longer than 1.6s are shortened (the live scene waits about 30s for the agent's state save before running `pisentry report`), and words like `critical`, `FAIL` and `PS04` in uncolored output are colored the way an editor theme would color them.

Record a single scene with `scripts/demo/record.py ./pisentry out/ --scene reload`. The `.cast` files also play in `asciinema play`.
