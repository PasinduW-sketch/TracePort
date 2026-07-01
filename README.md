# TracePort - Network Port Scanner

A high-performance, multi-threaded network port scanner built with Python. Features both a user-friendly GUI and powerful CLI interface.

## Features

- ✨ Multi-threaded port scanning (1-500 threads)
- 🎨 Tkinter GUI interface
- 💻 Command-line interface (CLI)
- 📊 Banner grabbing for service detection
- 📁 JSON and CSV export
- 🚀 Fast concurrent scanning
- 🔍 Hostname resolution
- 🛡️ Comprehensive error handling

## Installation

```bash
git clone https://github.com/PasinduW-sketch/TracePort.git
cd TracePort
pip install -r requirements.txt
```

## Usage

### GUI Mode (Default)
```bash
python main.py
```

### CLI Mode
```bash
python main.py localhost
python main.py 192.168.1.1 -p 1-1000
python main.py example.com -p 80,443,8080 --threads 100
python main.py target.com -o results.json --csv results.csv
```

## Requirements

- Python 3.8+
- tkinter (usually included with Python)
- tabulate (for formatted output)

## License

MIT License

## Author

PasinduW-sketch
