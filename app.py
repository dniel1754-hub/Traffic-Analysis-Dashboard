# =============================================================================
# PCAP Dashboard - Network Traffic Analysis Dashboard (Version 1)
# =============================================================================
# This tool receives a PCAP or PCAPNG file and displays detailed information:
# 1. General capture info (packet count, times, endpoints, protocols, charts)
# 2. HTTP transaction recovery (requests, responses, headers, payload & stream)
# 3. AI-powered questions about the captured data with concrete evidence
# 4. Creativity features: HTTP Response Time Chart, HTTP vs HTTPS Security
#    Comparison, Error Detection, and Automated Report Generation
# =============================================================================

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import (
    rdpcap,       # Function to read PCAP/PCAPNG files
    IP,           # IPv4 layer - source and destination addresses
    IPv6,         # IPv6 layer support (edge case handling)
    TCP,          # TCP layer - ports, sequence numbers, and flags
    UDP,          # UDP layer
    DNS,          # DNS layer
    Raw,          # Raw payload data (application content)
)
from scapy.layers.http import (
    HTTPRequest,  # HTTP request (GET, POST, etc.)
    HTTPResponse, # HTTP response (200 OK, 404, etc.)
)
from datetime import datetime
import tempfile
import os

# ──────────────────────────────────────────────────────────────────────────────
# Page Configuration
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PCAP Traffic Analysis Dashboard",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 PCAP / PCAPNG Network Analysis Dashboard")
st.markdown("**Automated network traffic extraction, HTTP transaction reconstruction, and AI-assisted packet analysis**")
st.markdown("---")


# =============================================================================
# Helper Functions
# =============================================================================

def get_ip_addresses(packet):
    """
    Safely extracts source and destination IP addresses from a packet.
    Supports both IPv4 and IPv6 (edge case handling).
    """
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return "N/A", "N/A"


def get_protocol_name(packet):
    """
    Identifies the highest-level (application/transport) protocol in a packet.
    """
    # 1. Check for HTTP (via Scapy HTTP layers or raw HTTP signatures)
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        return "HTTP"
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        if raw_bytes.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"HTTP/1.")):
            return "HTTP"

    # 2. Check for HTTPS / TLS (typically TCP port 443)
    if packet.haslayer(TCP) and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
        return "HTTPS/TLS"

    # 3. Check for DNS
    if packet.haslayer(DNS):
        return "DNS"

    # 4. Traverse layers to find the highest informative layer
    layer = packet
    protocol = "Unknown"
    while layer:
        name = layer.__class__.__name__
        if name not in ["Raw", "Padding", "Ether", "Dot1Q", "CookedLinux"]:
            protocol = name
        layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None
    return protocol


def parse_raw_http_headers(raw_text):
    """
    Helper function to extract headers and body from raw HTTP text.
    Useful both as a fallback and for displaying the full HTTP Stream.
    """
    headers = {}
    body = ""
    if "\r\n\r\n" in raw_text:
        header_part, body = raw_text.split("\r\n\r\n", 1)
    else:
        header_part = raw_text

    lines = header_part.split("\r\n")
    first_line = lines[0] if lines else ""
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    return first_line, headers, body


def extract_http_transactions(packets):
    """
    Extracts HTTP transactions and matches each request to its corresponding response.
    Also extracts all fields needed to answer the manual assignment questions:
    - Method, URI, Host, HTTP Version, User-Agent, Form/POST parameters
    - Status Code, Reason Phrase, Server Header, Content-Type, Content-Length
    - TCP segment count and Full HTTP Stream text
    """
    transactions = []
    # Dictionary mapping stream_key -> list of pending requests (queue for Keep-Alive connections)
    pending_requests = {}

    for i, pkt in enumerate(packets):
        frame_number = i + 1
        src_ip, dst_ip = get_ip_addresses(pkt)
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 0
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 0
        pkt_time = float(pkt.time)

        # Raw payload as text (if exists)
        raw_text = ""
        if pkt.haslayer(Raw):
            raw_text = pkt[Raw].load.decode('utf-8', errors='replace')

        # ──── Check if packet is an HTTP Request ────
        is_http_req = pkt.haslayer(HTTPRequest)
        if not is_http_req and pkt.haslayer(TCP) and raw_text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
            is_http_req = True

        # ──── Check if packet is an HTTP Response ────
        is_http_resp = pkt.haslayer(HTTPResponse)
        if not is_http_resp and pkt.haslayer(TCP) and raw_text.startswith("HTTP/1."):
            is_http_resp = True

        if is_http_req:
            first_line, headers, body = parse_raw_http_headers(raw_text)

            if pkt.haslayer(HTTPRequest):
                http_req = pkt[HTTPRequest]
                method = http_req.Method.decode('utf-8', errors='ignore') if http_req.Method else "N/A"
                uri = http_req.Path.decode('utf-8', errors='ignore') if http_req.Path else "N/A"
                host = http_req.Host.decode('utf-8', errors='ignore') if http_req.Host else headers.get("host", "N/A")
                version = http_req.Http_Version.decode('utf-8', errors='ignore') if http_req.Http_Version else "HTTP/1.1"
                user_agent = http_req.User_Agent.decode('utf-8', errors='ignore') if http_req.User_Agent else headers.get("user-agent", "N/A")
            else:
                parts = first_line.split(" ")
                method = parts[0] if len(parts) > 0 else "N/A"
                uri = parts[1] if len(parts) > 1 else "N/A"
                version = parts[2] if len(parts) > 2 else "HTTP/1.1"
                host = headers.get("host", "N/A")
                user_agent = headers.get("user-agent", "N/A")

            # Construct readable raw request text for "Follow HTTP Stream"
            full_req_raw = bytes(pkt[HTTPRequest]).decode('utf-8', errors='replace') if pkt.haslayer(HTTPRequest) else raw_text

            stream_key = (src_ip, src_port, dst_ip, dst_port)
            req_data = {
                "method": method,
                "uri": uri,
                "host": host,
                "http_version": version,
                "user_agent": user_agent,
                "req_body": body.strip() if body else "None",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "req_time": pkt_time,
                "req_frame": frame_number,
                "req_raw": full_req_raw,
            }
            pending_requests.setdefault(stream_key, []).append(req_data)

        elif is_http_resp:
            first_line, headers, body = parse_raw_http_headers(raw_text)

            if pkt.haslayer(HTTPResponse):
                http_resp = pkt[HTTPResponse]
                status_code = http_resp.Status_Code.decode('utf-8', errors='ignore') if http_resp.Status_Code else "N/A"
                reason = http_resp.Reason_Phrase.decode('utf-8', errors='ignore') if http_resp.Reason_Phrase else ""
                server_hdr = http_resp.Server.decode('utf-8', errors='ignore') if http_resp.Server else headers.get("server", "Not Present")
                content_type = http_resp.Content_Type.decode('utf-8', errors='ignore') if http_resp.Content_Type else headers.get("content-type", "Not Present")
                content_length = http_resp.Content_Length.decode('utf-8', errors='ignore') if http_resp.Content_Length else headers.get("content-length", "Not Present")
            else:
                parts = first_line.split(" ", 2)
                status_code = parts[1] if len(parts) > 1 else "N/A"
                reason = parts[2] if len(parts) > 2 else ""
                server_hdr = headers.get("server", "Not Present")
                content_type = headers.get("content-type", "Not Present")
                content_length = headers.get("content-length", "Not Present")

            full_resp_raw = bytes(pkt[HTTPResponse]).decode('utf-8', errors='replace') if pkt.haslayer(HTTPResponse) else raw_text

            # Reversed stream key: Response goes from Server -> Client
            stream_key = (dst_ip, dst_port, src_ip, src_port)

            if stream_key in pending_requests and len(pending_requests[stream_key]) > 0:
                req_info = pending_requests[stream_key].pop(0)
                response_time_ms = (pkt_time - req_info["req_time"]) * 1000

                # Count how many TCP data segments the server sent between request and response
                tcp_segments = 0
                for p_idx in range(req_info["req_frame"] - 1, frame_number):
                    p = packets[p_idx]
                    p_src, p_dst = get_ip_addresses(p)
                    if p.haslayer(TCP) and p_src == src_ip and p_dst == dst_ip:
                        if p[TCP].sport == src_port and p[TCP].dport == dst_port and len(p[TCP].payload) > 0:
                            tcp_segments += 1

                transactions.append({
                    "method": req_info["method"],
                    "uri": req_info["uri"],
                    "host": req_info["host"],
                    "http_version": req_info["http_version"],
                    "user_agent": req_info["user_agent"],
                    "req_body": req_info["req_body"],
                    "src_ip": req_info["src_ip"],
                    "dst_ip": req_info["dst_ip"],
                    "src_port": req_info["src_port"],
                    "dst_port": req_info["dst_port"],
                    "status_code": f"{status_code} {reason}".strip(),
                    "status_code_num": status_code,
                    "server_header": server_hdr,
                    "content_type": content_type,
                    "content_length": content_length,
                    "tcp_segments": max(1, tcp_segments),
                    "response_time_ms": round(response_time_ms, 2),
                    "req_frame": req_info["req_frame"],
                    "resp_frame": frame_number,
                    "req_timestamp": req_info["req_time"],
                    "resp_timestamp": pkt_time,
                    "req_raw": req_info["req_raw"],
                    "resp_raw": full_resp_raw,
                })

    # Add unanswered requests (edge case: no response received before capture ended)
    for stream_key, req_list in pending_requests.items():
        for req_info in req_list:
            transactions.append({
                "method": req_info["method"],
                "uri": req_info["uri"],
                "host": req_info["host"],
                "http_version": req_info["http_version"],
                "user_agent": req_info["user_agent"],
                "req_body": req_info["req_body"],
                "src_ip": req_info["src_ip"],
                "dst_ip": req_info["dst_ip"],
                "src_port": req_info["src_port"],
                "dst_port": req_info["dst_port"],
                "status_code": "No Response",
                "status_code_num": "N/A",
                "server_header": "N/A",
                "content_type": "N/A",
                "content_length": "N/A",
                "tcp_segments": 0,
                "response_time_ms": None,
                "req_frame": req_info["req_frame"],
                "resp_frame": None,
                "req_timestamp": req_info["req_time"],
                "resp_timestamp": None,
                "req_raw": req_info["req_raw"],
                "resp_raw": "No response recorded in capture.",
            })

    # Sort transactions chronologically by Request Frame
    transactions.sort(key=lambda x: x["req_frame"])
    return transactions


def build_packet_summary(packets, transactions, selected_transaction=None):
    """
    Builds a structured text summary of the extracted PCAP data for the AI model.
    Includes general stats, endpoint counts, HTTP transactions, the currently
    selected stream (Section 31), and frame-level details with timestamps.
    """
    summary_lines = []
    summary_lines.append("=== PCAP CAPTURE SUMMARY ===")
    summary_lines.append(f"Total packets: {len(packets)}")

    if len(packets) > 0:
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = end_time - start_time
        summary_lines.append(f"Start time: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S.%f')}")
        summary_lines.append(f"End time: {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S.%f')}")
        summary_lines.append(f"Duration: {duration:.3f} seconds")

    # Protocol distribution
    protocol_counts = {}
    for pkt in packets:
        proto = get_protocol_name(pkt)
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    summary_lines.append("\n=== PROTOCOL DISTRIBUTION ===")
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        summary_lines.append(f"{proto}: {count} packets")

    # Top endpoint IP addresses
    ip_counts = {}
    for pkt in packets:
        src, dst = get_ip_addresses(pkt)
        if src != "N/A":
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1

    summary_lines.append("\n=== TOP ENDPOINT IP ADDRESSES ===")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:15]:
        summary_lines.append(f"{ip}: {count} packets")

    # Detailed HTTP Transactions
    if transactions:
        summary_lines.append("\n=== EXTRACTED HTTP TRANSACTIONS ===")
        for idx, t in enumerate(transactions):
            summary_lines.append(
                f"Transaction #{idx+1}: Method={t['method']} | Host={t['host']} | URI={t['uri']} | "
                f"Version={t['http_version']} | Client={t['src_ip']}:{t['src_port']} -> Server={t['dst_ip']}:{t['dst_port']} | "
                f"Status={t['status_code']} | ResponseTime={t['response_time_ms']}ms | "
                f"ReqFrame=#{t['req_frame']} | RespFrame=#{t['resp_frame']} | "
                f"ServerHeader={t['server_header']} | ContentType={t['content_type']} | ContentLength={t['content_length']} | "
                f"UserAgent={t['user_agent']} | RequestBody/Params={t['req_body']}"
            )

    # Currently Selected Transaction / Stream (Directly supports Section 31!)
    if selected_transaction:
        summary_lines.append("\n=== CURRENTLY SELECTED HTTP STREAM / TRANSACTION BY USER ===")
        summary_lines.append(
            f"Selected Transaction: {selected_transaction['method']} {selected_transaction['host']}{selected_transaction['uri']} "
            f"(Request Frame #{selected_transaction['req_frame']}, Response Frame #{selected_transaction['resp_frame']})"
        )
        summary_lines.append(f"--- Client Request Stream ---\n{selected_transaction['req_raw'][:1500]}")
        summary_lines.append(f"--- Server Response Stream ---\n{selected_transaction['resp_raw'][:1500]}")

    # Frame-by-frame packet list (first 500 packets)
    summary_lines.append("\n=== PACKET DETAILS (First 500 Frames) ===")
    for i, pkt in enumerate(packets[:500]):
        frame = i + 1
        timestamp = float(pkt.time)
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")
        proto = get_protocol_name(pkt)
        src_ip, dst_ip = get_ip_addresses(pkt)

        line = f"Frame #{frame} | Time: {time_str} | Proto: {proto} | {src_ip} -> {dst_ip} | Len: {len(pkt)}B"

        if pkt.haslayer(TCP):
            line += f" | TCP {pkt[TCP].sport}->{pkt[TCP].dport} [Flags: {pkt[TCP].flags}]"
        elif pkt.haslayer(UDP):
            line += f" | UDP {pkt[UDP].sport}->{pkt[UDP].dport}"

        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            m = req.Method.decode('utf-8', errors='ignore') if req.Method else ""
            p = req.Path.decode('utf-8', errors='ignore') if req.Path else ""
            h = req.Host.decode('utf-8', errors='ignore') if req.Host else ""
            line += f" | HTTP Request: {m} {h}{p}"
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            s = resp.Status_Code.decode('utf-8', errors='ignore') if resp.Status_Code else ""
            line += f" | HTTP Response: Status {s}"

        summary_lines.append(line)

    return "\n".join(summary_lines)


def ask_ai(question, context, api_key, model_name="gemini-2.5-flash"):
    """
    Sends the user's question and extracted PCAP summary to Gemini AI.
    Forces the model to provide verifiable evidence (Frames, Timestamps, IPs).
    """
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)

        prompt = f"""You are a senior network traffic analysis expert assisting a computer science student.
Below is structured data extracted directly from a PCAP/PCAPNG file.

STRICT RULES:
1. Answer ONLY based on the extracted PCAP data provided below. Never invent or guess data.
2. ALWAYS include a dedicated "📌 Evidence from PCAP:" section in your answer citing exact Frame numbers (e.g., Frame #12), exact Timestamps, IP addresses, Ports, and HTTP headers/fields.
3. If the user asks about "the selected stream" or "selected transaction", refer to the section "=== CURRENTLY SELECTED HTTP STREAM / TRANSACTION BY USER ===".
4. Answer in the exact same language as the user's question (if asked in Hebrew, answer clearly in Hebrew).

=== EXTRACTED PCAP DATA ===
{context}
=== END OF DATA ===

User Question: {question}
"""
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"❌ Error communicating with Gemini AI: {str(e)}"


# =============================================================================
# Part 1: Loading the Capture (Sections 23-26)
# =============================================================================
st.header("📂 1. Load Capture File (סעיפים 23–26)")
st.markdown("Upload a **PCAP** or **PCAPNG** file to extract packet metrics, endpoints, protocols, and interactive visualizations.")

# ── Section 23: Choose a PCAP or PCAPNG file ──
uploaded_file = st.file_uploader(
    "Choose a PCAP or PCAPNG file",
    type=["pcap", "pcapng"],
    help="Upload your Wireshark capture file (.pcap or .pcapng)"
)

if uploaded_file is not None:
    # Preserve original extension (.pcap or .pcapng) for Scapy compatibility
    file_ext = os.path.splitext(uploaded_file.name)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    with st.spinner("⏳ Reading and parsing packets from capture file..."):
        packets = rdpcap(tmp_path)

    os.unlink(tmp_path)

    if len(packets) == 0:
        st.error("❌ The uploaded capture file contains 0 packets.")
        st.stop()

    st.success(f"✅ File **`{uploaded_file.name}`** loaded successfully! Found **{len(packets):,}** packets.")

    # ══════════════════════════════════════════════════════════════════════
    # Section 24: Packet count, start time, end time, and capture duration
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("📊 General Capture Information (סעיף 24)")

    start_ts = float(packets[0].time)
    end_ts = float(packets[-1].time)
    start_time = datetime.fromtimestamp(start_ts)
    end_time = datetime.fromtimestamp(end_ts)
    duration_seconds = end_ts - start_ts

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📦 Total Packets", f"{len(packets):,}")
    with col2:
        st.metric("🕐 Start Time", start_time.strftime("%H:%M:%S.%f")[:-3])
    with col3:
        st.metric("🕐 End Time", end_time.strftime("%H:%M:%S.%f")[:-3])
    with col4:
        st.metric("⏱️ Capture Duration", f"{duration_seconds:.3f} sec")

    st.caption(f"📅 **Full Start Timestamp:** `{start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}` (Frame #1) | **Full End Timestamp:** `{end_time.strftime('%Y-%m-%d %H:%M:%S.%f')}` (Frame #{len(packets)})")
    st.markdown("---")

    # ══════════════════════════════════════════════════════════════════════
    # Section 25: Main endpoint addresses AND main protocols found
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("🌐 Main Endpoint Addresses & Protocols (סעיף 25)")

    ip_counts = {}
    for pkt in packets:
        src, dst = get_ip_addresses(pkt)
        if src != "N/A":
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1

    if ip_counts:
        sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
        st.markdown("**🖥️ Top Endpoint IP Addresses (Source / Destination involvement):**")
        ip_col1, ip_col2 = st.columns(2)

        with ip_col1:
            ip_df = pd.DataFrame(sorted_ips, columns=["IP Address", "Packets Involved"])
            ip_df["Share of Capture"] = (ip_df["Packets Involved"] / len(packets) * 100).round(1).astype(str) + "%"
            st.dataframe(ip_df, use_container_width=True, hide_index=True)

        with ip_col2:
            fig_ip = px.bar(
                ip_df,
                x="Packets Involved",
                y="IP Address",
                orientation="h",
                title="Top 10 Endpoint IP Addresses",
                color="Packets Involved",
                color_continuous_scale="Blues"
            )
            fig_ip.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_ip, use_container_width=True)

    # ── Main Protocols ──
    st.markdown("**📡 Main Protocols Found:**")
    protocol_counts = {}
    for pkt in packets:
        proto = get_protocol_name(pkt)
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    sorted_protocols = sorted(protocol_counts.items(), key=lambda x: -x[1])
    proto_df = pd.DataFrame(sorted_protocols, columns=["Protocol", "Packet Count"])
    proto_df["Percentage"] = (proto_df["Packet Count"] / len(packets) * 100).round(1).astype(str) + "%"

    p_col1, p_col2 = st.columns(2)
    with p_col1:
        st.dataframe(proto_df, use_container_width=True, hide_index=True)
    with p_col2:
        fig_pie = px.pie(
            proto_df,
            names="Protocol",
            values="Packet Count",
            title="Protocol Distribution",
            hole=0.35
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("---")

    # ══════════════════════════════════════════════════════════════════════
    # Section 26: Visual Display - Traffic Volume Over Time & Filtering
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("📈 Traffic Visualizations & Interactive Filter (סעיף 26)")

    traffic_df = pd.DataFrame({
        "frame": range(1, len(packets) + 1),
        "timestamp": [datetime.fromtimestamp(float(pkt.time)) for pkt in packets],
        "size": [len(pkt) for pkt in packets],
        "protocol": [get_protocol_name(pkt) for pkt in packets],
    })

    all_protocols = sorted(traffic_df["protocol"].unique())
    selected_protocols = st.multiselect(
        "🔍 Filter visualizations by Protocol (leave empty to display all):",
        options=all_protocols,
        default=[]
    )

    filtered_df = traffic_df[traffic_df["protocol"].isin(selected_protocols)] if selected_protocols else traffic_df

    if len(filtered_df) > 0:
        time_series = filtered_df.set_index("timestamp").resample("1s")["size"].sum().reset_index()
        time_series.columns = ["Time", "Volume (Bytes)"]

        v_col1, v_col2 = st.columns(2)
        with v_col1:
            fig_traffic = px.line(
                time_series,
                x="Time",
                y="Volume (Bytes)",
                markers=True,
                title="📊 Traffic Volume Over Time (Bytes / Second)"
            )
            fig_traffic.update_layout(hovermode="x unified")
            st.plotly_chart(fig_traffic, use_container_width=True)

        with v_col2:
            proto_bar = filtered_df["protocol"].value_counts().reset_index()
            proto_bar.columns = ["Protocol", "Packet Count"]
            fig_bar = px.bar(
                proto_bar,
                x="Protocol",
                y="Packet Count",
                title="📊 Packet Count by Protocol",
                color="Protocol"
            )
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.warning("No packets match the selected filter.")

    st.markdown("---")

    # =====================================================================
    # Part 2: HTTP Transaction Recovery (Sections 27-29)
    # =====================================================================
    st.header("🔄 2. Reconstructing Manual HTTP Answers (סעיפים 27–29)")
    st.markdown("""
    Automatically matches **HTTP Requests** with their **HTTP Responses** over the same TCP 4-tuple stream
    (`Client_IP:Client_Port <-> Server_IP:Server_Port`) and extracts all fields from the manual Wireshark section.
    """)

    with st.spinner("🔍 Extracting HTTP transactions and streams..."):
        transactions = extract_http_transactions(packets)

    selected_transaction = None

    if len(transactions) > 0:
        st.success(f"✅ Automatically matched **{len(transactions)}** HTTP transactions!")

        # ── Section 28: Table with ALL required columns (including Source & Dest Ports!) ──
        trans_df = pd.DataFrame(transactions)
        display_cols = [
            "method", "host", "uri", "src_ip", "src_port",
            "dst_ip", "dst_port", "status_code", "response_time_ms",
            "req_frame", "resp_frame"
        ]
        display_names = {
            "method": "Method",
            "host": "Host",
            "uri": "URI (Path)",
            "src_ip": "Source IP",
            "src_port": "Src Port",
            "dst_ip": "Dest IP",
            "dst_port": "Dst Port",
            "status_code": "Status Code",
            "response_time_ms": "Response Time (ms)",
            "req_frame": "Request Frame #",
            "resp_frame": "Response Frame #",
        }
        st.dataframe(trans_df[display_cols].rename(columns=display_names), use_container_width=True, hide_index=True)

        # ── Section 29: Select a transaction and inspect full manual details & HTTP Stream ──
        st.subheader("🔎 Inspect Selected HTTP Transaction & Follow HTTP Stream (סעיף 29)")

        transaction_options = [
            f"Transaction #{i+1} | {t['method']} http://{t['host']}{t['uri']} | Status: {t['status_code']} (Frames #{t['req_frame']} -> #{t['resp_frame']})"
            for i, t in enumerate(transactions)
        ]

        selected_idx = st.selectbox(
            "Select an HTTP Transaction to inspect its full details and stream:",
            range(len(transaction_options)),
            format_func=lambda i: transaction_options[i]
        )

        if selected_idx is not None:
            selected_transaction = transactions[selected_idx]
            t = selected_transaction

            col_req, col_resp = st.columns(2)
            with col_req:
                st.markdown("### 📤 HTTP Request Details (Answers to Q8, Q13)")
                st.markdown(f"- **Request Frame Number:** `Frame #{t['req_frame']}`")
                st.markdown(f"- **Timestamp:** `{datetime.fromtimestamp(t['req_timestamp']).strftime('%H:%M:%S.%f')}`")
                st.markdown(f"- **HTTP Method:** `{t['method']}`")
                st.markdown(f"- **HTTP Version:** `{t['http_version']}`")
                st.markdown(f"- **Host:** `{t['host']}`")
                st.markdown(f"- **Requested Path (URI):** `{t['uri']}`")
                st.markdown(f"- **Source (Client IP:Port):** `{t['src_ip']}:{t['src_port']}`")
                st.markdown(f"- **Destination (Server IP:Port):** `{t['dst_ip']}:{t['dst_port']}`")
                st.markdown(f"- **Client Details (User-Agent):** `{t['user_agent']}`")
                st.markdown(f"- **Sent Parameters / Body (POST/Form):** `{t['req_body']}`")

            with col_resp:
                st.markdown("### 📥 HTTP Response Details (Answers to Q9, Q10, Q11)")

                resp_frame_text = f"Frame #{t['resp_frame']}" if t['resp_frame'] else "No Response"
                st.markdown(f"- **Response Frame Number:** `{resp_frame_text}`")

                if t['resp_timestamp']:
                    st.markdown(f"- **Timestamp:** `{datetime.fromtimestamp(t['resp_timestamp']).strftime('%H:%M:%S.%f')}`")

                resp_time_text = f"{t['response_time_ms']} ms ({t['response_time_ms']/1000:.4f} sec)" if t['response_time_ms'] is not None else "N/A"
                st.markdown(f"- **Response Time (Delta):** `{resp_time_text}`")

                st.markdown(f"- **Status Code:** `{t['status_code']}`")
                st.markdown(f"- **Server IP Address:** `{t['dst_ip']}`")
                st.markdown(f"- **Server Header:** `{t['server_header']}`")
                st.markdown(f"- **Content-Type:** `{t['content_type']}`")
                st.markdown(f"- **Content-Length:** `{t['content_length']}`")
                st.markdown(f"- **TCP Data Segments in Response:** `{t['tcp_segments']} segment(s)`")

            # Follow HTTP Stream view (Answers Q16-Q18)
            with st.expander("📜 Follow Full HTTP Stream (Request & Response Payload - Q16-Q18)", expanded=False):
                s_col1, s_col2 = st.columns(2)
                with s_col1:
                    st.markdown("**Client -> Server (Request Stream):**")
                    st.code(t["req_raw"], language="http")
                with s_col2:
                    st.markdown("**Server -> Client (Response Stream):**")
                    st.code(t["resp_raw"][:4000], language="http")
    else:
        st.info("ℹ️ No unencrypted HTTP transactions were found in this capture file (the file may contain only HTTPS/TLS or other protocols).")

    st.markdown("---")

    # =====================================================================
    # Part 3: Creativity Section (יצירתיות - מעבר לדרישות הבסיס)
    # =====================================================================
    st.header("💡 3. Creativity & Advanced Insights (פרק יצירתיות)")
    st.markdown("""
    To help the user deeply understand the capture beyond basic tables, this module provides:
    1. **HTTP Response Time & Status Code Analyzer** (identifies bottlenecks and HTTP 4xx/5xx errors).
    2. **HTTP vs. HTTPS (TLS) Visibility & Privacy Comparison** (automatically connects to Manual Questions 19–22).
    3. **One-Click Automated Markdown Report Export**.
    """)

    tab1, tab2, tab3 = st.tabs([
        "⏱️ HTTP Response Times & Error Detector",
        "🔒 HTTP vs. HTTPS Visibility Analyzer",
        "📄 Export Automated Summary Report"
    ])

    with tab1:
        if len(transactions) > 0:
            valid_trans = [t for t in transactions if t["response_time_ms"] is not None]
            if valid_trans:
                rt_df = pd.DataFrame(valid_trans)
                rt_df["Label"] = rt_df.apply(lambda r: f"#{r['req_frame']} {r['method']} {r['uri']}", axis=1)

                fig_rt = px.bar(
                    rt_df,
                    x="Label",
                    y="response_time_ms",
                    color="status_code",
                    title="⏱️ HTTP Response Time per Transaction (ms) Colored by Status Code",
                    labels={"Label": "Transaction (Frame & URI)", "response_time_ms": "Response Time (ms)"}
                )
                st.plotly_chart(fig_rt, use_container_width=True)

                # Highlight slowest request & any HTTP errors (4xx / 5xx)
                slowest = max(valid_trans, key=lambda x: x["response_time_ms"])
                st.info(
                    f"🐢 **Slowest HTTP Request:** `{slowest['method']} http://{slowest['host']}{slowest['uri']}` "
                    f"took **{slowest['response_time_ms']} ms** (Request `Frame #{slowest['req_frame']}` -> Response `Frame #{slowest['resp_frame']}`)."
                )

                errors = [t for t in transactions if str(t["status_code_num"]).startswith(("4", "5")) or t["status_code"] == "No Response"]
                if errors:
                    st.warning(f"⚠️ **Detected {len(errors)} HTTP Error / Unanswered Transaction(s):**")
                    for err in errors:
                        st.markdown(f"- `Frame #{err['req_frame']}`: `{err['method']} {err['host']}{err['uri']}` -> Status: **`{err['status_code']}`**")
                else:
                    st.success("✅ All HTTP transactions completed without 4xx/5xx errors!")
        else:
            st.info("No HTTP transactions available to chart response times.")

    with tab2:
        http_pkts = [p for p in packets if get_protocol_name(p) == "HTTP"]
        https_pkts = [p for p in packets if get_protocol_name(p) == "HTTPS/TLS"]

        c1, c2 = st.columns(2)
        with c1:
            st.metric("🔓 Unencrypted HTTP Packets", len(http_pkts))
            st.markdown("""
            **What is visible in HTTP?**
            - ✅ Source & Destination IP, Ports, Packet Sizes, Timestamps
            - ✅ **Full URL / URI path** (`GET /forms/post`)
            - ✅ **HTTP Headers** (`Host`, `User-Agent`, `Server`, `Cookie`)
            - ✅ **Form parameters & Payload Body** in plain text!
            """)
        with c2:
            st.metric("🔒 Encrypted HTTPS / TLS Packets (Port 443)", len(https_pkts))
            st.markdown("""
            **What is visible vs. hidden in HTTPS (Q19–Q22)?**
            - ✅ **Still Visible:** IP Addresses, TCP Ports (443), Packet Sizes, Timestamps, TCP Flags, and TLS Handshake metadata (SNI).
            - ❌ **Hidden (Encrypted):** HTTP Method, exact URI path, Headers (`User-Agent`, `Cookies`), Status Code, and Payload Body.
            - 🕵️ **Traffic Analysis Risk (Q22):** Even when encrypted, packet timing, burst frequency, data volume, and destination IPs can reveal user activity patterns (e.g., video streaming vs. web browsing vs. file download).
            """)

    with tab3:
        report_md = f"""# Automated PCAP Analysis Report
- **File Name:** `{uploaded_file.name}`
- **Total Packets:** {len(packets)}
- **Start Time:** {start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}
- **End Time:** {end_time.strftime('%Y-%m-%d %H:%M:%S.%f')}
- **Duration:** {duration_seconds:.3f} seconds
- **HTTP Transactions Found:** {len(transactions)}

## Protocol Breakdown
{proto_df.to_markdown(index=False)}
"""
        st.download_button(
            label="📥 Download Summary Report (.md)",
            data=report_md,
            file_name=f"pcap_report_{uploaded_file.name}.md",
            mime="text/markdown"
        )

    st.markdown("---")

    # =====================================================================
    # Part 4: AI-Powered Questions (Sections 30-34)
    # =====================================================================
    st.header("🤖 4. AI-Powered Traffic Assistant (סעיפים 30–34)")
    st.markdown("""
    Ask free-form questions in Hebrew or English! The AI receives **only the structured data extracted by our Python code**
    (not the raw binary PCAP file) and is strictly instructed to cite **Evidence** (`Frame #`, `Timestamps`, `IPs`).
    """)

    ai_col1, ai_col2 = st.columns([2, 1])
    with ai_col1:
        api_key = st.text_input(
            "🔑 Enter your Gemini API Key:",
            type="password",
            help="Get a key from Google AI Studio (do NOT hardcode or submit your API key in the ZIP!)"
        )
    with ai_col2:
        model_choice = st.selectbox(
            "🧠 Gemini Model:",
            ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"],
            index=0
        )

    # Quick-select sample questions (Directly supports Section 31 & 33!)
    st.markdown("**💡 Quick Question Templates (Click to populate or type your own below):**")
    sample_questions = [
        "כתוב שאלה חופשית משלך...",
        "איזו בקשת HTTP הייתה הכי איטית, מה היה זמן התגובה שלה ואיזה Status Code חזר?",
        "כמה בקשות HTTP נשלחו לכל Host בהקלטה?",
        "מה קרה ב-Stream (טרנזקציה) שנבחר כרגע בדשבורד? מה נשלח מהלקוח ומה חזר מהשרת?",
        "באילו כתובות IP ופורטים השתמשו הלקוח והשרת בבקשת ה-HTTP הראשונה, ואיזה דפדפן (User-Agent) שלח אותה?",
        "מהו מספר החבילות הכולל בהקלטה, מה משך ההקלטה ומהם הפרוטוקולים המרכזיים?"
    ]
    chosen_template = st.selectbox("Choose a sample question or write your own:", sample_questions)

    default_q = "" if chosen_template == "כתוב שאלה חופשית משלך..." else chosen_template
    user_question = st.text_area(
        "💬 Write your question for the AI:",
        value=default_q,
        placeholder="לדוגמה: איזו בקשה הייתה הכי איטית? מה קרה ב-Stream שנבחר?",
        height=100
    )

    if st.button("🚀 Ask the AI (with PCAP Evidence)", type="primary"):
        if not api_key:
            st.error("❌ Please enter a Gemini API Key first.")
        elif not user_question.strip():
            st.error("❌ Please enter a question.")
        else:
            with st.spinner("📝 Building structured context from extracted PCAP data..."):
                context = build_packet_summary(packets, transactions, selected_transaction)

            with st.spinner("🤖 Analyzing extracted traffic data and verifying frame evidence..."):
                answer = ask_ai(user_question, context, api_key, model_choice)

            st.markdown("### 📋 AI Answer & Evidence:")
            st.markdown(answer)

            with st.expander("🔍 View Exact Extracted Evidence Sent to the AI (Transparency Check)"):
                st.text(context)

else:
    st.info("👆 Please upload a `.pcap` or `.pcapng` file above to start analyzing network traffic.")
