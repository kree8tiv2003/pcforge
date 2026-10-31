"""Single place for the product name and look. Change these and the whole app follows."""

NAME = "PCForge"              # placeholder: replace with your own product name
TAGLINE = "Clean. Tune. Protect."
VERSION = "0.1.2"
DATA_FOLDER = NAME            # created under %LOCALAPPDATA%
HOSTS_MARKER = NAME.upper()   # tags the block we add to the hosts file

# Updates. UPDATE_MANIFEST_URL is where you upload latest.json (must be https). Empty = updates not set up yet.
UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/kree8tiv2003/pcforge/updates/latest.json"
UPDATE_PUBLIC_KEY = "2jI2Y08CEAT1diEQFKJ3YTLHJWFG3cfEzDz7PI1FhNo="   # matches the private key in ~\PCForge-keys

# GUI palette
BG = "#10131a"
PANEL = "#171c26"
ACCENT = "#ff7a1a"
ACCENT_DARK = "#c85a0a"
TEXT = "#e8ecf3"
MUTED = "#8b95a7"
GOOD = "#3ecf8e"
WARN = "#f5c542"
BAD = "#ff5c5c"
