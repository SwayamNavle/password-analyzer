"""
app.py
------
Password Cracking & Strength Analyzer Tool
Main Streamlit application entry point.

Run with:
    streamlit run app.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import time
import json
from datetime import datetime

# ── Module imports ──────────────────────────────────────────────────────────
from modules.strength_analyzer import analyze_password, compare_passwords
from modules.hash_generator import generate_all_hashes, HASH_EDUCATION
from modules.attack_simulator import (
    dictionary_attack, brute_force_attack, hybrid_attack,
    load_wordlist, run_all_attacks,
)
from modules.report_generator import generate_report


# ════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="PassCrack Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ════════════════════════════════════════════════════════════════════════════
# CUSTOM CSS — Dark cybersecurity aesthetic
# ════════════════════════════════════════════════════════════════════════════
def inject_css():
    st.markdown("""
    <style>
    /* ── Google Font ── */
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;500;600&display=swap');

    /* ── Root palette ── */
    :root {
        --bg-primary:   #0a0e1a;
        --bg-card:      #0f1628;
        --bg-panel:     #111827;
        --accent-cyan:  #00f5ff;
        --accent-green: #00ff88;
        --accent-red:   #ff3366;
        --accent-yellow:#ffd700;
        --accent-orange:#ff6b00;
        --text-primary: #e2e8f0;
        --text-muted:   #64748b;
        --border:       #1e2d4a;
        --glow-cyan:    0 0 20px rgba(0,245,255,0.3);
        --glow-green:   0 0 20px rgba(0,255,136,0.3);
        --glow-red:     0 0 20px rgba(255,51,102,0.3);
    }

    /* ── Global overrides ── */
    .stApp {
        background: var(--bg-primary) !important;
        font-family: 'Inter', sans-serif !important;
    }
    .main .block-container {
        padding-top: 1rem !important;
        max-width: 1400px !important;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: var(--bg-card) !important;
        border-right: 1px solid var(--border) !important;
    }
    section[data-testid="stSidebar"] * {
        color: var(--text-primary) !important;
    }

    /* ── Headers ── */
    h1, h2, h3 { font-family: 'Orbitron', sans-serif !important; }

    /* ── Custom hero header ── */
    .hero-header {
        background: linear-gradient(135deg, #0f1628 0%, #1a2744 50%, #0f1628 100%);
        border: 1px solid var(--accent-cyan);
        border-radius: 12px;
        padding: 2rem;
        text-align: center;
        position: relative;
        overflow: hidden;
        margin-bottom: 1.5rem;
        box-shadow: var(--glow-cyan);
    }
    .hero-header::before {
        content: '';
        position: absolute;
        top: -50%; left: -50%;
        width: 200%; height: 200%;
        background: radial-gradient(circle at center, rgba(0,245,255,0.05) 0%, transparent 70%);
        animation: pulse 4s ease-in-out infinite;
    }
    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 0.5; }
        50% { transform: scale(1.1); opacity: 1; }
    }
    .hero-title {
        font-family: 'Orbitron', sans-serif !important;
        font-size: 2.4rem !important;
        font-weight: 900 !important;
        background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        margin: 0 !important;
        letter-spacing: 2px !important;
    }
    .hero-subtitle {
        color: var(--text-muted) !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.9rem !important;
        margin-top: 0.5rem !important;
        letter-spacing: 1px !important;
    }

    /* ── Metric cards ── */
    .metric-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        transition: all 0.3s ease;
    }
    .metric-card:hover { border-color: var(--accent-cyan); box-shadow: var(--glow-cyan); }
    .metric-value {
        font-family: 'Orbitron', sans-serif;
        font-size: 2rem;
        font-weight: 700;
        color: var(--accent-cyan);
        line-height: 1.2;
    }
    .metric-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.72rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 0.3rem;
    }

    /* ── Strength bar ── */
    .strength-bar-container {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    .strength-bar-outer {
        background: #1a2340;
        border-radius: 50px;
        height: 24px;
        overflow: hidden;
        position: relative;
        border: 1px solid var(--border);
    }
    .strength-bar-inner {
        height: 100%;
        border-radius: 50px;
        transition: width 0.6s cubic-bezier(0.4,0,0.2,1);
        position: relative;
        overflow: hidden;
    }
    .strength-bar-inner::after {
        content: '';
        position: absolute;
        top: 0; left: -100%;
        width: 100%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        animation: shimmer 2s infinite;
    }
    @keyframes shimmer { to { left: 100%; } }

    /* Strength colors */
    .bar-red     { background: linear-gradient(90deg, #ff1744, #ff3366); }
    .bar-orange  { background: linear-gradient(90deg, #ff6b00, #ff9500); }
    .bar-yellow  { background: linear-gradient(90deg, #ffd700, #ffed4a); }
    .bar-blue    { background: linear-gradient(90deg, #0088ff, #00bfff); }
    .bar-green   { background: linear-gradient(90deg, #00cc66, #00ff88); }

    /* ── Hash display ── */
    .hash-block {
        background: #060c18;
        border: 1px solid var(--border);
        border-left: 3px solid var(--accent-cyan);
        border-radius: 6px;
        padding: 0.8rem 1rem;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem;
        color: var(--accent-cyan);
        word-break: break-all;
        line-height: 1.6;
        margin: 0.4rem 0;
    }
    .hash-block.insecure {
        border-left-color: var(--accent-red);
        color: var(--accent-red);
    }
    .hash-block.secure {
        border-left-color: var(--accent-green);
        color: var(--accent-green);
    }

    /* ── Attack log terminal ── */
    .terminal {
        background: #020408;
        border: 1px solid #1a3a1a;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.82rem;
        color: #33ff33;
        min-height: 200px;
        max-height: 350px;
        overflow-y: auto;
        white-space: pre-wrap;
        line-height: 1.8;
    }
    .terminal-header {
        background: #1a3a1a;
        border-radius: 6px 6px 0 0;
        padding: 0.4rem 1rem;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.78rem;
        color: #33ff33;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    /* ── Rule badges ── */
    .rule-pass {
        display: inline-block;
        background: rgba(0,255,136,0.1);
        border: 1px solid var(--accent-green);
        color: var(--accent-green);
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.72rem;
        font-family: 'Share Tech Mono', monospace;
        margin: 2px;
    }
    .rule-fail {
        display: inline-block;
        background: rgba(255,51,102,0.1);
        border: 1px solid var(--accent-red);
        color: var(--accent-red);
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.72rem;
        font-family: 'Share Tech Mono', monospace;
        margin: 2px;
    }

    /* ── Alert boxes ── */
    .alert-danger {
        background: rgba(255,51,102,0.1);
        border: 1px solid var(--accent-red);
        border-radius: 8px;
        padding: 1rem;
        color: var(--accent-red);
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.85rem;
        animation: blink-border 1s ease infinite alternate;
    }
    .alert-success {
        background: rgba(0,255,136,0.08);
        border: 1px solid var(--accent-green);
        border-radius: 8px;
        padding: 1rem;
        color: var(--accent-green);
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.85rem;
    }
    @keyframes blink-border {
        from { border-color: var(--accent-red); }
        to   { border-color: rgba(255,51,102,0.3); }
    }

    /* ── Crack time table ── */
    .crack-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
    }
    .crack-table th {
        background: #0a1628;
        color: var(--accent-cyan);
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid var(--border);
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .crack-table td {
        padding: 8px 12px;
        color: var(--text-primary);
        border-bottom: 1px solid var(--border);
    }
    .crack-table tr:hover td { background: rgba(0,245,255,0.04); }

    /* ── Section title ── */
    .section-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1rem;
        color: var(--accent-cyan);
        letter-spacing: 2px;
        text-transform: uppercase;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border);
        margin-bottom: 1rem;
    }

    /* ── Streamlit overrides ── */
    .stTextInput > div > div > input {
        background: #0a1628 !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1.1rem !important;
        padding: 0.8rem !important;
        letter-spacing: 1px !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: var(--accent-cyan) !important;
        box-shadow: var(--glow-cyan) !important;
    }
    .stButton > button {
        background: linear-gradient(135deg, #0a1628, #162040) !important;
        border: 1px solid var(--accent-cyan) !important;
        color: var(--accent-cyan) !important;
        font-family: 'Orbitron', sans-serif !important;
        font-size: 0.78rem !important;
        letter-spacing: 1px !important;
        border-radius: 6px !important;
        transition: all 0.3s ease !important;
        padding: 0.6rem 1.2rem !important;
        text-transform: uppercase !important;
    }
    .stButton > button:hover {
        background: rgba(0,245,255,0.1) !important;
        box-shadow: var(--glow-cyan) !important;
        transform: translateY(-1px) !important;
    }
    div[data-testid="stRadio"] label {
        color: var(--text-primary) !important;
        font-family: 'Inter', sans-serif !important;
    }
    .stSelectbox > div > div {
        background: #0a1628 !important;
        border-color: var(--border) !important;
        color: var(--text-primary) !important;
    }
    div[data-testid="stExpander"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: var(--text-muted) !important;
        font-family: 'Orbitron', sans-serif !important;
        font-size: 0.75rem !important;
        letter-spacing: 1px !important;
    }
    .stTabs [aria-selected="true"] {
        color: var(--accent-cyan) !important;
        border-bottom-color: var(--accent-cyan) !important;
    }
    p, li, div { color: var(--text-primary) !important; }
    .stMarkdown code {
        background: #060c18 !important;
        color: var(--accent-cyan) !important;
        font-family: 'Share Tech Mono', monospace !important;
    }
    [data-testid="metric-container"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
        padding: 1rem !important;
    }
    </style>
    """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# HELPER COMPONENTS
# ════════════════════════════════════════════════════════════════════════════

def render_hero():
    st.markdown("""
    <div class="hero-header">
        <div class="hero-title">🔐 PASSCRACK ANALYZER</div>
        <div class="hero-subtitle">
            [ PASSWORD SECURITY INTELLIGENCE SYSTEM v2.0 ] — EDUCATIONAL USE ONLY
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_strength_bar(score: int, label: str, color: str):
    color_map = {
        "red":    "bar-red",
        "orange": "bar-orange",
        "yellow": "bar-yellow",
        "blue":   "bar-blue",
        "green":  "bar-green",
        "gray":   "bar-red",
    }
    bar_class = color_map.get(color, "bar-red")

    label_colors = {
        "Very Weak":  "#ff3366",
        "Weak":       "#ff6b00",
        "Fair":       "#ffd700",
        "Strong":     "#0088ff",
        "Very Strong": "#00ff88",
        "—":          "#64748b",
    }
    label_color = label_colors.get(label, "#64748b")

    st.markdown(f"""
    <div class="strength-bar-container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
            <span style="font-family:'Orbitron',sans-serif; font-size:0.7rem; 
                         text-transform:uppercase; letter-spacing:2px; color:#64748b;">
                STRENGTH RATING
            </span>
            <span style="font-family:'Orbitron',sans-serif; font-size:1.1rem; 
                         font-weight:700; color:{label_color};">
                {label} &nbsp; <span style="font-size:0.85rem; color:#64748b;">{score}/100</span>
            </span>
        </div>
        <div class="strength-bar-outer">
            <div class="strength-bar-inner {bar_class}" style="width:{score}%;"></div>
        </div>
        <div style="display:flex; justify-content:space-between; 
                    margin-top:0.4rem; font-family:'Share Tech Mono',monospace; 
                    font-size:0.65rem; color:#2d4a6e;">
            <span>VERY WEAK</span><span>WEAK</span><span>FAIR</span><span>STRONG</span><span>VERY STRONG</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_metrics_row(analysis: dict):
    cols = st.columns(4)
    metrics = [
        ("LENGTH",    str(analysis["length"]),           "chars"),
        ("ENTROPY",   f"{analysis['entropy']:.1f}",       "bits"),
        ("CHARSET",   str(analysis["charset_size"]),      "symbols"),
        ("SCORE",     str(analysis["strength_score"]),    "/ 100"),
    ]
    for col, (label, val, sub) in zip(cols, metrics):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{val}</div>
                <div class="metric-label">{label} <span style="color:#2d4a6e">{sub}</span></div>
            </div>
            """, unsafe_allow_html=True)


def render_rule_badges(rules: dict):
    rule_labels = {
        "length_8":       "≥8 chars",
        "length_12":      "≥12 chars",
        "length_16":      "≥16 chars",
        "has_uppercase":  "Uppercase",
        "has_lowercase":  "Lowercase",
        "has_digit":      "Digits",
        "has_special":    "Special chars",
        "no_repeating":   "No repeats",
        "no_sequential":  "No sequences",
        "not_common":     "Not common",
    }
    badges = ""
    for key, label in rule_labels.items():
        cls = "rule-pass" if rules.get(key) else "rule-fail"
        icon = "✓" if rules.get(key) else "✗"
        badges += f'<span class="{cls}">{icon} {label}</span>'

    st.markdown(f"""
    <div style="margin:0.8rem 0;">
        <div class="section-title">RULE CHECKS</div>
        <div>{badges}</div>
    </div>
    """, unsafe_allow_html=True)


def render_crack_table(crack_times: dict):
    rows = ""
    for attack, t in crack_times.items():
        danger = "color:#ff3366" if any(x in t for x in ["second", "minute", "hour", "day"]) else ""
        rows += f"<tr><td>{attack}</td><td style='{danger}'>{t}</td></tr>"

    st.markdown(f"""
    <div class="section-title">ESTIMATED CRACK TIMES</div>
    <table class="crack-table">
        <tr><th>Attack Vector</th><th>Time to Crack</th></tr>
        {rows}
    </table>
    """, unsafe_allow_html=True)


def render_terminal(log_lines: list, title="ATTACK LOG"):
    content = "\n".join(log_lines) if log_lines else "Awaiting attack initiation..."
    st.markdown(f"""
    <div>
        <div class="terminal-header">
            <span>⬤</span><span>⬤</span><span>⬤</span>
            &nbsp;&nbsp; {title}
        </div>
        <div class="terminal">{content}</div>
    </div>
    """, unsafe_allow_html=True)


def render_attack_result(result: dict):
    if result["success"]:
        st.markdown(f"""
        <div class="alert-danger">
            ⚠️  PASSWORD CRACKED!<br>
            Found: <strong>{result['found']}</strong><br>
            Attempts: {result['attempts']:,} &nbsp;|&nbsp; 
            Time: {result['elapsed_ms']:.1f} ms &nbsp;|&nbsp;
            Speed: {result['speed']:,} attempts/sec
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="alert-success">
            ✅ PASSWORD WITHSTOOD ATTACK<br>
            Exhausted {result['attempts']:,} attempts in {result['elapsed_ms']:.1f} ms
        </div>
        """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ════════════════════════════════════════════════════════════════════════════

def init_session():
    defaults = {
        "password_history": [],
        "last_analysis": None,
        "show_password": False,
        "attack_log": [],
        "attack_ran": False,
        "last_attack_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ════════════════════════════════════════════════════════════════════════════

def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding:1rem 0; border-bottom:1px solid #1e2d4a; margin-bottom:1rem;">
            <div style="font-family:'Orbitron',sans-serif; font-size:1.2rem; 
                         color:#00f5ff; letter-spacing:2px;">🔐 MENU</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "Navigate",
            ["🏠 Dashboard", "🔑 Strength Analyzer", "🔒 Hash Generator",
             "💀 Attack Simulator", "📊 Comparison", "📚 Learn Security",
             "📋 History & Reports"],
            label_visibility="collapsed",
        )

        st.markdown("---")
        st.markdown("""
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.72rem; 
                     color:#2d4a6e; padding:0.5rem;">
            ⚠️ For educational purposes only.<br>
            Never use these techniques on systems<br>
            you don't own or have permission to test.
        </div>
        """, unsafe_allow_html=True)

        if st.session_state.get("last_analysis"):
            a = st.session_state["last_analysis"]
            st.markdown("---")
            st.markdown(f"""
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.72rem; color:#64748b;">
                LAST ANALYZED<br>
                <span style="color:#00f5ff">{a['strength_label']}</span> — 
                <span style="color:#64748b">{a['entropy']:.1f} bits</span>
            </div>
            """, unsafe_allow_html=True)

    return page


# ════════════════════════════════════════════════════════════════════════════
# PAGES
# ════════════════════════════════════════════════════════════════════════════

def page_dashboard():
    """Overview / landing page."""
    render_hero()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="metric-card" style="text-align:left;">
            <div style="font-size:2rem">🔍</div>
            <div style="font-family:'Orbitron',sans-serif; color:#00f5ff; font-size:0.85rem; margin:0.5rem 0;">
                STRENGTH ANALYZER
            </div>
            <div style="font-size:0.82rem; color:#64748b;">
                Entropy calculation, rule checks, crack time estimates, 
                and actionable improvement suggestions.
            </div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card" style="text-align:left;">
            <div style="font-size:2rem">🔒</div>
            <div style="font-family:'Orbitron',sans-serif; color:#00ff88; font-size:0.85rem; margin:0.5rem 0;">
                HASH GENERATOR
            </div>
            <div style="font-size:0.82rem; color:#64748b;">
                SHA-256, SHA-512, MD5 hashing with salting. 
                Learn why hashing protects stored passwords.
            </div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card" style="text-align:left;">
            <div style="font-size:2rem">💀</div>
            <div style="font-family:'Orbitron',sans-serif; color:#ff3366; font-size:0.85rem; margin:0.5rem 0;">
                ATTACK SIMULATOR
            </div>
            <div style="font-size:0.82rem; color:#64748b;">
                Dictionary, brute force, and hybrid attacks simulated 
                in real-time with live progress logs.
            </div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Quick analyze
    st.markdown('<div class="section-title">⚡ QUICK ANALYZE</div>', unsafe_allow_html=True)
    pw = st.text_input(
        "Enter a password to instantly analyze",
        type="password",
        key="quick_pw",
        placeholder="Type your password here...",
    )

    if pw:
        analysis = analyze_password(pw)
        st.session_state["last_analysis"] = analysis

        render_strength_bar(analysis["strength_score"], analysis["strength_label"], analysis["strength_color"])
        render_metrics_row(analysis)

        if analysis["is_common"]:
            st.markdown("""
            <div class="alert-danger">
                🚨 CRITICAL: This password appears in known breach databases! 
                Change it immediately on all accounts!
            </div>""", unsafe_allow_html=True)

        st.markdown("**Security Suggestions:**")
        for sug in analysis["suggestions"]:
            st.markdown(f"- {sug}")

    # Stats box
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">📡 SYSTEM STATUS</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    wl = load_wordlist()
    history_len = len(st.session_state.get("password_history", []))
    with c1:
        st.metric("Wordlist Size",   f"{len(wl):,}")
    with c2:
        st.metric("Passwords Tested", str(history_len))
    with c3:
        st.metric("Attack Algorithms", "3")
    with c4:
        st.metric("Hash Algorithms",   "5")


def page_strength_analyzer():
    st.markdown('<div class="section-title">🔑 PASSWORD STRENGTH ANALYZER</div>', unsafe_allow_html=True)

    col_input, col_toggle = st.columns([5, 1])
    with col_toggle:
        show = st.checkbox("👁 Show", value=st.session_state["show_password"])
        st.session_state["show_password"] = show

    with col_input:
        pw_type = "default" if show else "password"
        pw = st.text_input(
            "Password",
            type=pw_type,
            key="analyzer_pw",
            placeholder="Enter password to analyze...",
            label_visibility="collapsed",
        )

    if not pw:
        st.info("Enter a password above to see real-time analysis.")
        return

    analysis = analyze_password(pw)
    st.session_state["last_analysis"] = analysis

    # Track history
    history = st.session_state["password_history"]
    if not history or history[-1]["password"] != pw:
        history.append({
            "password": pw,
            "score": analysis["strength_score"],
            "label": analysis["strength_label"],
            "entropy": analysis["entropy"],
            "time": datetime.now().strftime("%H:%M:%S"),
        })
        # Keep max 20 entries
        st.session_state["password_history"] = history[-20:]

    # ── Strength bar ──
    render_strength_bar(analysis["strength_score"], analysis["strength_label"], analysis["strength_color"])

    # ── Metrics ──
    render_metrics_row(analysis)
    st.markdown("")

    left, right = st.columns(2)

    with left:
        render_rule_badges(analysis["rules"])

        st.markdown("")
        st.markdown('<div class="section-title">💡 SUGGESTIONS</div>', unsafe_allow_html=True)
        for sug in analysis["suggestions"]:
            st.markdown(f"<div style='margin:0.3rem 0; font-size:0.88rem;'>{sug}</div>",
                        unsafe_allow_html=True)

    with right:
        render_crack_table(analysis["crack_times"])

        st.markdown("")
        st.markdown('<div class="section-title">📐 ENTROPY BREAKDOWN</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="hash-block">
  Password Length  : {analysis['length']} characters
  Charset Size     : {analysis['charset_size']} possible symbols
  Entropy Formula  : {analysis['length']} × log₂({analysis['charset_size']})
  Entropy Result   : {analysis['entropy']:.2f} bits
  Combinations     : ~{2**analysis['entropy']:.2e} guesses needed
        </div>
        """, unsafe_allow_html=True)

    # Common password warning
    if analysis["is_common"]:
        st.markdown("""
        <div class="alert-danger" style="margin-top:1rem;">
            🚨 BREACH DATABASE MATCH DETECTED<br>
            This password appears in known wordlists used by attackers. 
            It would be cracked almost instantly in a dictionary attack.
            Change it on every service where you use it — immediately.
        </div>
        """, unsafe_allow_html=True)


def page_hash_generator():
    st.markdown('<div class="section-title">🔒 CRYPTOGRAPHIC HASH GENERATOR</div>', unsafe_allow_html=True)

    pw = st.text_input(
        "Password to hash",
        type="password",
        key="hash_pw",
        placeholder="Enter password to generate hashes...",
        label_visibility="collapsed",
    )

    if not pw:
        st.info("Enter a password to generate hashes.")
        with st.expander("📚 Why do we hash passwords?"):
            st.markdown(HASH_EDUCATION["why_hash"])
        with st.expander("🧂 What is a cryptographic salt?"):
            st.markdown(HASH_EDUCATION["why_salt"])
        return

    hashes = generate_all_hashes(pw)
    gen_time = hashes.pop("_time_ms", 0)

    st.markdown(f"""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:#2d4a6e; margin-bottom:1rem;">
        Generated {len(hashes)} hashes in {gen_time:.3f} ms
    </div>
    """, unsafe_allow_html=True)

    for algo, info in hashes.items():
        secure = info.get("secure", False)
        css_class = "secure" if secure else "insecure"
        status_label = "✓ SECURE" if secure else "⚠️  INSECURE"
        status_color = "#00ff88" if secure else "#ff3366"
        bits = info.get("bits", "?")

        st.markdown(f"""
        <div style="margin-bottom:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;
                        font-family:'Share Tech Mono',monospace; font-size:0.78rem; margin-bottom:4px;">
                <span style="color:#00f5ff; font-weight:bold;">{algo}</span>
                <span>
                    <span style="color:#64748b;">{bits}-bit</span> &nbsp;
                    <span style="color:{status_color};">{status_label}</span>
                </span>
            </div>
            <div class="hash-block {css_class}">{info['hash']}</div>
        </div>
        """, unsafe_allow_html=True)

    # Avalanche effect demo
    st.markdown("")
    st.markdown('<div class="section-title">🌊 AVALANCHE EFFECT DEMO</div>', unsafe_allow_html=True)
    st.markdown(
        "Change *one character* and the entire hash transforms completely. "
        "This is how hash functions protect integrity."
    )

    import hashlib
    h_original = hashlib.sha256(pw.encode()).hexdigest()
    pw_modified = pw[:-1] + (chr(ord(pw[-1]) + 1) if pw else "a")
    h_modified  = hashlib.sha256(pw_modified.encode()).hexdigest()

    # Highlight differences
    diff_html = ""
    for c1, c2 in zip(h_original, h_modified):
        if c1 != c2:
            diff_html += f'<span style="color:#ff3366;font-weight:bold;">{c2}</span>'
        else:
            diff_html += c2

    changed_chars = sum(1 for a, b in zip(h_original, h_modified) if a != b)

    st.markdown(f"""
    <div class="hash-block secure" style="margin-bottom:0.5rem;">
Original  [{pw[:20]}...]:  {h_original}
    </div>
    <div class="hash-block insecure">
Modified  [{pw_modified[:20]}...]:  {diff_html}
    </div>
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.78rem; 
                color:#ffd700; margin-top:0.5rem;">
        {changed_chars} of 64 characters changed ({changed_chars/64*100:.0f}%) 
        from a single character modification.
    </div>
    """, unsafe_allow_html=True)

    with st.expander("📚 Hash Algorithm Comparison"):
        for algo, desc in HASH_EDUCATION["algorithms_compared"].items():
            st.markdown(f"**{algo}**: {desc}")


def page_attack_simulator():
    st.markdown('<div class="section-title">💀 ATTACK SIMULATION MODULE</div>', unsafe_allow_html=True)

    st.markdown("""
    <div style="background:rgba(255,51,102,0.08); border:1px solid #ff3366; border-radius:8px; 
                padding:0.8rem 1rem; font-family:'Share Tech Mono',monospace; font-size:0.78rem; 
                color:#ff6b6b; margin-bottom:1.5rem;">
        ⚠️  EDUCATIONAL SIMULATION — These attacks run locally against a password you provide.
        This tool simulates real-world techniques to help you understand vulnerabilities.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])
    with col1:
        target = st.text_input(
            "Target Password (to simulate cracking)",
            key="attack_target",
            placeholder="Enter a password to test against attacks...",
        )

    with col2:
        attack_type = st.selectbox(
            "Attack Type",
            ["Dictionary Attack", "Brute Force Attack", "Hybrid Attack", "Run All Attacks"],
            key="attack_type",
        )

    # Attack-specific settings
    with st.expander("⚙️ Attack Settings"):
        c1, c2, c3 = st.columns(3)
        with c1:
            max_attempts = st.number_input(
                "Max Attempts",
                min_value=100,
                max_value=1_000_000,
                value=50_000,
                step=1000,
            )
        with c2:
            max_length = st.number_input(
                "Brute Force Max Length",
                min_value=1,
                max_value=6,
                value=4,
            )
        with c3:
            charset = st.selectbox(
                "Brute Force Charset",
                ["Lowercase + Digits", "Lowercase Only", "Digits Only", "All Printable"],
            )

    charset_map = {
        "Lowercase + Digits": "abcdefghijklmnopqrstuvwxyz0123456789",
        "Lowercase Only":      "abcdefghijklmnopqrstuvwxyz",
        "Digits Only":         "0123456789",
        "All Printable":       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()",
    }

    if not target:
        st.info("Enter a target password above and choose an attack type.")
        # Show theoretical crack time
        return

    # ── Analysis of target ──
    analysis = analyze_password(target)
    mini_cols = st.columns(4)
    with mini_cols[0]: st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
    with mini_cols[1]: st.metric("Strength", analysis['strength_label'])
    with mini_cols[2]: st.metric("Length", f"{analysis['length']} chars")
    with mini_cols[3]: st.metric("Common?", "YES ⚠️" if analysis["is_common"] else "No ✓")

    st.markdown("")
    launch_btn = st.button(f"⚡ LAUNCH {attack_type.upper()}", use_container_width=True)

    if launch_btn:
        st.session_state["attack_ran"] = True
        wordlist = load_wordlist()

        with st.spinner("🔴 ATTACK IN PROGRESS..."):
            progress = st.progress(0)
            status_box = st.empty()

            # Simulate progress animation
            for i in range(0, 100, 10):
                progress.progress(i)
                status_box.markdown(
                    f'<div class="alert-danger">💀 Trying combinations... {i}% complete</div>',
                    unsafe_allow_html=True,
                )
                time.sleep(0.08)

            # Run actual attack
            if attack_type == "Dictionary Attack":
                result = dictionary_attack(target, wordlist, int(max_attempts))
            elif attack_type == "Brute Force Attack":
                cs = charset_map.get(charset, charset_map["Lowercase + Digits"])
                result = brute_force_attack(target, cs, int(max_length), int(max_attempts))
            elif attack_type == "Hybrid Attack":
                result = hybrid_attack(target, wordlist, int(max_attempts))
            else:
                # Run all — return combined log
                results = run_all_attacks(target, wordlist)
                combined_log = []
                any_success = False
                for atype, r in results.items():
                    combined_log.append(f"\n=== {r['attack_type'].upper()} ===")
                    combined_log.extend(r["log"])
                    if r["success"]:
                        any_success = True
                        result = r
                if not any_success:
                    result = list(results.values())[-1]
                    result["log"] = combined_log
                    result["success"] = False

            progress.progress(100)
            status_box.empty()

        st.session_state["last_attack_result"] = result
        st.session_state["attack_log"] = result["log"]

    # ── Display results ──
    if st.session_state["attack_ran"] and st.session_state.get("last_attack_result"):
        result = st.session_state["last_attack_result"]

        st.markdown("")
        render_attack_result(result)
        st.markdown("")

        left, right = st.columns(2)
        with left:
            render_terminal(st.session_state["attack_log"])
        with right:
            st.markdown('<div class="section-title">📊 ATTACK STATS</div>', unsafe_allow_html=True)
            st.markdown(f"""
            <div class="hash-block">
  Attack Type    : {result['attack_type']}
  Total Attempts : {result['attempts']:,}
  Time Taken     : {result['elapsed_ms']:.2f} ms
  Attack Speed   : {result['speed']:,} attempts/sec
  Result         : {'CRACKED ✓' if result['success'] else 'FAILED ✗'}
  Found          : {result['found'] if result['found'] else 'N/A'}
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-title" style="margin-top:1rem;">🧠 WHAT THIS MEANS</div>',
                        unsafe_allow_html=True)
            if result["success"]:
                st.markdown("""
                <div style="font-size:0.85rem; line-height:1.7; color:#ff6b6b;">
                    ❌ Your password was cracked! This means:<br>
                    • It appears in common wordlists<br>
                    • It uses predictable patterns<br>
                    • An attacker could crack it quickly<br>
                    • You should change it immediately
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style="font-size:0.85rem; line-height:1.7; color:#33ff33;">
                    ✅ Attack failed (within demo limits). This means:<br>
                    • Not in common wordlists<br>
                    • Too complex for quick brute force<br>
                    • Good entropy and length<br>
                    • Real attacks take longer but are still possible
                </div>
                """, unsafe_allow_html=True)


def page_comparison():
    st.markdown('<div class="section-title">📊 PASSWORD COMPARISON TOOL</div>', unsafe_allow_html=True)
    st.markdown("Compare two passwords side-by-side to see which is stronger and why.")

    col1, col2 = st.columns(2)
    with col1:
        pw1 = st.text_input("Password A", type="password", key="cmp_pw1",
                             placeholder="Enter first password...")
    with col2:
        pw2 = st.text_input("Password B", type="password", key="cmp_pw2",
                             placeholder="Enter second password...")

    if not pw1 or not pw2:
        st.info("Enter two passwords above to compare them.")
        return

    cmp = compare_passwords(pw1, pw2)
    a1  = cmp["password_1"]
    a2  = cmp["password_2"]

    st.markdown(f"""
    <div style="text-align:center; font-family:'Orbitron',sans-serif; font-size:1.1rem;
                color:#ffd700; padding:1rem; border:1px solid #ffd700; border-radius:8px;
                background:rgba(255,215,0,0.08); margin:1rem 0;">
        🏆 {cmp['winner']} is stronger by {cmp['entropy_diff']:.1f} bits of entropy
    </div>
    """, unsafe_allow_html=True)

    left, right = st.columns(2)

    for col, analysis, label in [(left, a1, "PASSWORD A"), (right, a2, "PASSWORD B")]:
        with col:
            st.markdown(f'<div class="section-title">{label}</div>', unsafe_allow_html=True)
            render_strength_bar(analysis["strength_score"], analysis["strength_label"],
                                analysis["strength_color"])
            st.markdown(f"""
            <div class="hash-block">
  Entropy  : {analysis['entropy']:.2f} bits
  Length   : {analysis['length']} chars
  Charset  : {analysis['charset_size']} symbols
  Score    : {analysis['strength_score']}/100
  Common?  : {'YES ⚠️' if analysis['is_common'] else 'No ✓'}
            </div>
            """, unsafe_allow_html=True)

            st.markdown("**Rule Checks:**")
            rules = analysis["rules"]
            for rk, rl in [("has_uppercase", "Uppercase"), ("has_lowercase", "Lowercase"),
                           ("has_digit", "Digits"), ("has_special", "Special chars"),
                           ("length_12", "≥12 chars"), ("not_common", "Not common")]:
                icon = "✅" if rules.get(rk) else "❌"
                st.markdown(f"{icon} {rl}")


def page_learn():
    st.markdown('<div class="section-title">📚 PASSWORD SECURITY EDUCATION</div>', unsafe_allow_html=True)

    tabs = st.tabs([
        "🔐 Password Basics",
        "🧂 Hashing & Salting",
        "💀 Attack Types",
        "🛡️ Best Practices",
        "📊 Entropy Guide",
    ])

    with tabs[0]:
        st.markdown("""
        ## What Makes a Password Strong?

        A strong password relies on **unpredictability**. Humans are terrible at 
        creating truly random passwords — we use names, dates, keyboard patterns, 
        and predictable substitutions.

        ### The Four Dimensions of Password Strength

        | Factor | Weak | Strong |
        |--------|------|--------|
        | Length | 6–8 chars | 16+ chars |
        | Charset | lowercase only | upper + lower + digits + symbols |
        | Randomness | words, names, dates | truly random |
        | Uniqueness | reused across sites | unique per site |

        ### Why Length Matters Most

        Adding characters exponentially increases the number of combinations:
        - 6 lowercase chars:  26⁶  = **309 million** combinations
        - 8 lowercase chars:  26⁸  = **209 billion** combinations
        - 12 mixed chars:     ~95¹² = **540 quintillion** combinations
        - 16 mixed chars:     ~95¹⁶ = **440 septillion** combinations

        Each additional character multiplies combinations by the charset size.
        """)

    with tabs[1]:
        st.markdown(HASH_EDUCATION["why_hash"])
        st.markdown(HASH_EDUCATION["why_salt"])
        st.markdown("### Algorithm Comparison")
        for algo, desc in HASH_EDUCATION["algorithms_compared"].items():
            st.markdown(f"**{algo}**: {desc}")

    with tabs[2]:
        st.markdown("""
        ## Password Attack Methods

        ### 1. 📖 Dictionary Attack
        Tries words from a list of known passwords and common words.
        - **Speed**: Very fast for matching passwords
        - **Coverage**: Only hits passwords in the list
        - **Defense**: Don't use dictionary words. Use random passphrases.

        ### 2. 💪 Brute Force Attack
        Tries every possible combination of characters up to a given length.
        - **Speed**: Exponentially slower as length increases
        - **Coverage**: Guaranteed to crack eventually (given enough time)
        - **Defense**: Use long passwords. 12+ chars makes brute force impractical.

        ### 3. 🔀 Hybrid Attack
        Combines dictionary words with mutations (numbers, symbols, l33tspeak).
        Specifically targets "smart" passwords like `P@ssw0rd1!`.
        - **Speed**: Faster than pure brute force, broader than dictionary
        - **Defense**: Avoid predictable substitutions on common words.

        ### 4. 🌈 Rainbow Table Attack
        Uses pre-computed tables of hash→password mappings.
        - **Defense**: Salting makes rainbow tables useless.

        ### 5. 🎭 Social Engineering / Phishing
        Tricks users into revealing passwords directly.
        - **Defense**: 2FA, password managers, phishing awareness.
        """)

    with tabs[3]:
        st.markdown("""
        ## Best Practices

        ### 🔑 Creating Passwords
        1. Use 16+ characters minimum
        2. Mix uppercase, lowercase, digits, and symbols
        3. Use a **passphrase**: `correct-horse-battery-staple`
        4. Never use personal information (name, birthday, pet's name)
        5. Avoid keyboard patterns (`qwerty`, `12345`)

        ### 🗄️ Storing Passwords
        1. **Use a password manager** (Bitwarden, 1Password, KeePass)
        2. Enable **Two-Factor Authentication** (2FA) everywhere
        3. Never write passwords on paper or in plain text files
        4. Never reuse passwords across different services

        ### 🔍 Checking Your Exposure
        1. Visit **haveibeenpwned.com** to check if your email was breached
        2. Enable breach monitoring in your password manager
        3. Change passwords immediately after any breach notification

        ### 🏢 For Developers
        1. Never store plain-text passwords
        2. Use **bcrypt** or **Argon2** for password hashing
        3. Add unique salts per user
        4. Enforce minimum password requirements
        5. Rate-limit login attempts
        """)

    with tabs[4]:
        st.markdown("""
        ## Understanding Password Entropy

        Entropy measures how **unpredictable** a password is.
        Formula: **H = L × log₂(N)**
        Where L = length, N = size of character set.

        | Entropy | Strength | Example |
        |---------|----------|---------|
        | < 28 bits | Very Weak | `abc12` |
        | 28–36 bits | Weak | `hello1!` |
        | 36–60 bits | Fair | `Tr0ub4dor` |
        | 60–80 bits | Strong | `xKm9#pLqT2w!` |
        | 80+ bits | Very Strong | `mX#9kP!2nL$qRw7` |

        ### Charset Size Reference

        | Characters Used | Charset Size (N) |
        |----------------|-----------------|
        | Digits only (0-9) | 10 |
        | Lowercase only (a-z) | 26 |
        | Lower + Upper | 52 |
        | Lower + Upper + Digits | 62 |
        | All printable ASCII | 95 |

        ### Real-World Attack Speeds (2024)

        | Hash Type | Guesses/Second |
        |-----------|---------------|
        | MD5 (GPU) | ~100 billion/sec |
        | SHA-256 (GPU) | ~8 billion/sec |
        | bcrypt | ~10,000/sec |
        | Argon2id | ~1,000/sec |

        This is why **bcrypt** and **Argon2** are preferred for password storage —
        they're deliberately slow to compute.
        """)


def page_history():
    st.markdown('<div class="section-title">📋 TEST HISTORY & REPORTS</div>', unsafe_allow_html=True)

    history = st.session_state.get("password_history", [])

    if not history:
        st.info("No passwords tested yet. Use the Strength Analyzer to add entries.")
        return

    st.markdown(f"**{len(history)} passwords analyzed this session** (passwords shown as score/label only)")

    # Table
    st.markdown("""
    <table class="crack-table" style="width:100%">
        <tr>
            <th>#</th>
            <th>Strength</th>
            <th>Score</th>
            <th>Entropy (bits)</th>
            <th>Time</th>
        </tr>
    """, unsafe_allow_html=True)

    rows_html = ""
    for i, entry in enumerate(history, 1):
        color_map = {
            "Very Weak":  "#ff3366",
            "Weak":       "#ff6b00",
            "Fair":       "#ffd700",
            "Strong":     "#0088ff",
            "Very Strong": "#00ff88",
        }
        color = color_map.get(entry['label'], '#64748b')
        rows_html += f"""
        <tr>
            <td>{i}</td>
            <td style="color:{color}; font-weight:bold;">{entry['label']}</td>
            <td>{entry['score']}/100</td>
            <td>{entry['entropy']:.2f}</td>
            <td style="color:#64748b;">{entry['time']}</td>
        </tr>
        """

    st.markdown(rows_html + "</table>", unsafe_allow_html=True)

    st.markdown("")

    # Generate report
    if st.button("📄 Generate Security Report"):
        last = st.session_state.get("last_analysis")
        if not last:
            st.warning("Analyze a password first to generate a report.")
        else:
            hashes = generate_all_hashes(last["password"])
            attack_res = {}
            if st.session_state.get("last_attack_result"):
                r = st.session_state["last_attack_result"]
                attack_res[r["attack_type"]] = r

            path = generate_report(last, hashes, attack_res)
            st.success(f"✅ Report saved: `{path}`")

            with open(path, "r") as f:
                report_text = f.read()
            st.download_button(
                label="⬇️ Download Report",
                data=report_text,
                file_name=os.path.basename(path),
                mime="text/plain",
            )

    if st.button("🗑️ Clear History"):
        st.session_state["password_history"] = []
        st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    inject_css()
    init_session()
    page = render_sidebar()

    page_map = {
        "🏠 Dashboard":          page_dashboard,
        "🔑 Strength Analyzer":  page_strength_analyzer,
        "🔒 Hash Generator":     page_hash_generator,
        "💀 Attack Simulator":   page_attack_simulator,
        "📊 Comparison":         page_comparison,
        "📚 Learn Security":     page_learn,
        "📋 History & Reports":  page_history,
    }

    fn = page_map.get(page, page_dashboard)
    fn()


if __name__ == "__main__":
    main()
