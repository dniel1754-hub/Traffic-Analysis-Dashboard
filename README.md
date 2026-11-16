# 🔍 PCAP / PCAPNG Network Traffic Analysis Dashboard (V1)

An interactive network traffic analysis dashboard built with **Python**, **Streamlit**, **Scapy**, **Plotly**, and **Google Gemini AI**.  
Developed for **Assignment 1 (Part C - Sections 23–34 & Creativity)** to automatically parse `.pcap` and `.pcapng` capture files, reconstruct manual Wireshark HTTP investigations, and answer free-form questions backed by concrete packet-level evidence.

---

## 🚀 Quick Start & Installation Guide

### 1. Prerequisites
- **Python 3.10+** installed on your system.
- **Npcap** (on Windows) or **libpcap** (on Linux/macOS) — automatically included if Wireshark is installed.

### 2. Installation
1. Extract the submitted `.zip` archive to a local folder and open a terminal in that directory.
2. (Recommended) Create and activate a virtual environment:
   - **Windows:**
     ```bash
     python -m venv .venv
     .venv\Scripts\activate
     ```
   - **Linux / macOS / WSL:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 3. Running the Dashboard
Launch the Streamlit application:
```bash
streamlit run app.py
```
The dashboard will automatically open in your default browser at `http://localhost:8501`.

---

## 📖 Dashboard Modules & Assignment Mapping

### 1. 📂 Load Capture File & Traffic Overview (Sections 23–26)
- **File Upload (Sec. 23):** Supports both `.pcap` and `.pcapng` files.
- **Capture Metrics (Sec. 24):** Displays total packet count, exact start time (`Frame #1`), end time, and total capture duration in seconds.
- **Main Endpoints & Protocols (Sec. 25):** Extracts and visualizes the Top 10 Endpoint IP Addresses (source/destination involvement) and full protocol distribution (`HTTP`, `HTTPS/TLS`, `DNS`, `TCP`, `UDP`, etc.) via interactive tables, bar charts, and donut charts.
- **Interactive Visualizations & Filtering (Sec. 26):** Plots traffic volume over time (`Bytes/Second`) and packet counts per protocol, with an interactive multi-protocol filter.

### 2. 🔄 HTTP Transaction Reconstruction (Sections 27–29)
- **Automated Request/Response Pairing (Sec. 27):** Matches HTTP requests and responses over the same TCP 4-tuple stream (`Client_IP:Client_Port <-> Server_IP:Server_Port`), including support for Keep-Alive queues and raw payload parsing.
- **Full Transactions Table (Sec. 28):** Displays `Method`, `Host`, `URI`, `Source IP`, `Src Port`, `Dest IP`, `Dst Port`, `Status Code`, `Response Time (ms)`, `Request Frame #`, and `Response Frame #`.
- **Deep Transaction & Stream Inspector (Sec. 29):** Select any transaction to view all fields required in the manual Wireshark section:
  - **Request:** Frame #, Timestamp, Method, HTTP Version, Host, URI, Client IP:Port, User-Agent, and sent POST/Form parameters (Body).
  - **Response:** Frame #, Timestamp, Delta Response Time (ms), Status Code, Server IP, Server header, Content-Type, Content-Length, and TCP segment count.
  - **Follow HTTP Stream:** Expandable viewer showing the complete raw HTTP Request and Response payloads side-by-side.

### 3. 💡 Creativity & Advanced Insights Module
- **HTTP Response Time & Error Detector:** Visualizes latency across all HTTP transactions, automatically highlights the slowest request, and flags HTTP `4xx`/`5xx` errors or unanswered requests.
- **HTTP vs. HTTPS (TLS) Visibility Analyzer:** Side-by-side comparison of unencrypted HTTP vs. encrypted HTTPS/TLS (Port 443) packets in the capture, explaining what remains visible (IPs, ports, sizes, timestamps, SNI) vs. encrypted, and why encrypted traffic is still vulnerable to traffic analysis (Questions 19–22).
- **One-Click Automated Markdown Report:** Generates and downloads a structured `.md` summary report of the capture.

### 4. 🤖 AI-Powered Traffic Assistant with Evidence (Sections 30–34)
- **Structured Context Extraction:** Instead of sending the raw binary PCAP to the LLM, the system extracts structured packet summaries, endpoint statistics, HTTP transactions, and the currently selected HTTP stream as grounded context.
- **Free-Form Q&A (Sec. 30–31):** Ask questions in Hebrew or English , for asking question you need to enter your API key (includes quick-select templates for slowest request, status codes, requests per host, and inspecting the selected stream).

- **Verifiable Evidence (Sec. 32):** The prompt enforces strict grounding — every answer cites exact `Frame #` numbers, `Timestamps`, IP addresses, and ports, accompanied by an expandable transparency viewer showing the exact extracted data sent to the model.
- **Security Note:** Your Gemini API Key is entered securely via a password input field in the UI and is never hardcoded or stored in the repository.

---

## 📁 Project Structure
```text
├── app.py              # Main Streamlit dashboard & Scapy analysis engine
├── requirements.txt    # Required Python packages
└── README.md           # Setup instructions and assignment documentation
```
