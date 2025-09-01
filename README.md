# AI PCAP Analyzer



An intelligent network packet capture analyzer that uses AI to explain network traffic patterns and anomalies. This tool processes PCAP files through Wireshark's `tshark` utility and leverages OpenAI's language models to provide human-readable analysis of network communications.



## Features



- 🔍 **Automated PCAP Analysis** - Converts binary packet captures to JSON and analyzes them

- 🤖 **AI-Powered Insights** - Uses OpenAI models to interpret network traffic patterns

- 📦 **Batch Processing** - Handles large captures by processing packets in configurable batches

- 📊 **Progress Tracking** - Visual ASCII progress bar for long-running analyses

- 💾 **File Output** - Saves both summary and detailed analysis to text files

- 🌍 **Custom Prompts** - Supports user-defined questions about the network traffic

- 🔧 **Flexible Configuration** - Environment-based configuration for different AI endpoints



## Prerequisites



### Required Software

- **Python 3.6+**

- **Wireshark** with `tshark` command-line utility

- **OpenAI Python library**: `pip install openai`



### System Installation



**Ubuntu/Debian:**

```bash

sudo apt-get update

sudo apt-get install wireshark-common

```



**macOS:**

```bash

brew install wireshark

```



**Windows:**

Download and install Wireshark from https://www.wireshark.org/download.html



## Installation



1. Clone or download the script

2. Install dependencies:

&nbsp;  ```bash

&nbsp;  pip install openai

&nbsp;  ```

3. Ensure `tshark` is available in your PATH



## Configuration



Create a `.env` file in the same directory as the script:



```env

OPENAI\_ENDPOINT=https://api.openai.com

OPENAI\_API\_KEY=your\_openai\_api\_key\_here

MODEL=gpt-4

```



### Configuration Options



| Variable | Description | Example |

|----------|-------------|---------|

| `OPENAI\_ENDPOINT` | API endpoint URL | `https://api.openai.com` |

| `OPENAI\_API\_KEY` | Your OpenAI API key | `sk-...` |

| `MODEL` | Model to use for analysis | `gpt-4`, `gpt-3.5-turbo` |



## Usage



### Basic Analysis

```bash

python ai\_pcap\_explain.py capture.pcap

```



### Custom Question

```bash

python ai\_pcap\_explain.py capture.pcap "What security issues can you identify?"

```



### Adjust Batch Size

```bash

python ai\_pcap\_explain.py capture.pcap --batch-size 20

```



### Complete Example

```bash

python ai\_pcap\_explain.py network\_trace.pcap "Analyze HTTP traffic patterns" --batch-size 15

```



## Output Files



The script generates two output files:



- **`summary.txt`** - Comprehensive summary combining insights from all packet batches

- **`details.txt`** - Detailed analysis of each individual batch



## How It Works



1. **Packet Extraction** - Uses `tshark` to convert PCAP to JSON format

2. **Batch Division** - Splits packets into manageable chunks for AI processing

3. **Batch Analysis** - Each batch is analyzed separately by the AI model

4. **Summary Generation** - All batch analyses are combined into a final comprehensive summary

5. **File Output** - Results are saved to text files and displayed on screen



## Use Cases



- **Network Troubleshooting** - Understand communication patterns and identify issues

- **Security Analysis** - Detect suspicious traffic patterns and potential threats

- **Protocol Analysis** - Learn how different network protocols behave in practice

- **Educational Tool** - Understand network communications with AI explanations

- **Forensic Investigation** - Analyze captured network evidence with AI assistance



## Example Output



```

🔍 Uruchamiam tshark na pliku 'capture.pcap'...

📦 Dzielę pakiety na porcje po 10...

📊 Znaleziono 156 pakietów w 16 porcjach

🚀 Rozpoczynam analizę porcji...

🤖 Analizuję: |██████████████████████████████████████████████████| 100.0% (16/16)

🎯 Tworzę końcowe podsumowanie...

💾 Zapisuję wyniki do plików...

✅ Podsumowanie zapisane do: summary.txt

✅ Szczegóły zapisane do: details.txt



===============================================================================

🎯 KOŃCOWE PODSUMOWANIE ANALIZY

===============================================================================

The network capture reveals primarily HTTP and DNS traffic between...

```



## Error Handling



The script includes comprehensive error handling for:

- Missing or invalid PCAP files

- Wireshark/tshark installation issues

- OpenAI API connection problems

- Invalid JSON responses

- File writing permissions



## Limitations



- Requires active internet connection for AI analysis

- API costs apply based on OpenAI pricing

- Large PCAP files may take significant time to process

- Analysis quality depends on the AI model used



## Troubleshooting



**"tshark binary not found"**

- Ensure Wireshark is installed and `tshark` is in your PATH



**"Missing keys in .env"**

- Verify your `.env` file contains all required variables

- Check that your OpenAI API key is valid



**"OpenAI request failed"**

- Verify your API key and endpoint configuration

- Check your internet connection

- Ensure you have sufficient API credits



## License



This project is provided as-is for educational and professional use. Please ensure compliance with OpenAI's usage policies when using this tool.



## Contributing



Feel free to submit issues, feature requests, or pull requests to improve the functionality and usability of this tool.

