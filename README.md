
# NopeWare

<img src="https://socialify.git.ci/PavinDas/VirusScanner/image?description=1&font=KoHo&language=1&name=1&owner=1&pattern=Solid&theme=Dark" alt="VirusScanner" width="640" height="320" />

This script allows you to upload a file to VirusTotal for analysis and retrieve the results using their API. It uses Python libraries requests, json, and colorama for handling HTTP requests, JSON parsing, and colored console output, respectively.


## Features

- Uploads a file for scanning.
- Retrieves detailed analysis, including file name, size, description, and SHA-256 hash.
- Displays antivirus scan results with categorized verdicts.
- Highlights if any antivirus detects the file as malicious.



## Installation

### Prerequisites

Ensure you have the following installed on your system:
- Python 3.6 or later
- Require Python libraries:
    - requests
    - colorama

Install the dependencies using pip:

```bash
  pip install requests colorama
```


## Setup

### Setup API key
**1.** Get an API Key:

Register at VirusTotal and obtain your API key.

**2.** Store the API Key:

Save your API key in a file named api-key.txt in the same directory as the script.

### Clone code

**1.** Initialize the script:
```bash
https://github.com/PavinDas/NopeWare.git
```
**2.** Open script folder:
```bash
cd NopeWare
```

**3.** Give execution permission:
```bash
chmod +x *
```
## Usage

**1.** Run the script :
```bash
python3 main.py
```
**2.** Provide the file path to the file you want to analyze when prompted:
```bash
Enter the file path >> /path/to/your/file
```

**3.** View the results directly in the console, including:
- File name
- File size
- Description
- SHA-256 hash
- Verdicts from various antivirus engines.
## Highlights
- Results are dynamically typed out to enhance interactivity.
- Malicious verdicts are flagged prominently for better visibility.
## Example Output

```yaml
Analyzing...

Name : test_file.exe
Size : 1234.56 KB
Description : Executable file
SHA-256 Hash : 123abc456def789...

Antivirus1: undetected
Antivirus2: malicious
...

2 antivirus found the given file malicious !!
```
[VirusScanner.webm](https://github.com/user-attachments/assets/0afcf631-09ed-4bda-b5e9-96f8cae2d0fe)


## 🛡️Ownership:

This project is owned by [Pavin Das](https://github.com/PavinDas)

