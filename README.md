# 🔐 PassCrack Analyzer
### Password Cracking & Strength Analyzer Tool

> A complete cybersecurity educational tool for analyzing password strength,
> simulating crack attacks, and learning cryptographic hashing.

---

## 📁 Project Structure

```
password_analyzer/
├── app.py                          # Main Streamlit application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── modules/
│   ├── __init__.py                 # Package init
│   ├── strength_analyzer.py        # Entropy + rule-based analysis
│   ├── hash_generator.py           # SHA-256/512/MD5 + salting
│   ├── attack_simulator.py         # Dictionary/Brute Force/Hybrid
│   └── report_generator.py         # Text report export
│
├── data/
│   └── wordlist.txt                # 100+ common password wordlist
│
└── exports/                        # Generated reports saved here
```

---

## ⚙️ Setup & Installation

### Requirements
- Python 3.10 or higher
- pip

### Step 1 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 2 — Run the application

```bash
streamlit run app.py
```

The app will open automatically at: **http://localhost:8501**

---

## 🎯 Features

### 1. 🏠 Dashboard
- Project overview
- Quick password analyzer
- System stats (wordlist size, algorithms loaded)

### 2. 🔑 Strength Analyzer
- Real-time entropy calculation using `H = L × log₂(N)`
- Rule-based checks (length, uppercase, digits, special chars, patterns)
- Strength meter with animated progress bar (red → green)
- Crack time estimates across 5 attack vectors
- Actionable improvement suggestions
- Common password detection

### 3. 🔒 Hash Generator
- SHA-256, SHA-512, MD5, SHA-1, Salted SHA-256
- Avalanche effect visualization (change 1 char → hash completely changes)
- Educational content: why hash? what is salt?

### 4. 💀 Attack Simulator
- **Dictionary Attack** — tries 100+ common passwords + variants
- **Brute Force Attack** — all combinations up to configurable length
- **Hybrid Attack** — dictionary + l33tspeak + number suffixes + symbols
- **Run All Attacks** — comprehensive simulation
- Live terminal output log
- Attack stats: attempts, time, speed (attempts/sec)
- Configurable max attempts, charset, length limits

### 5. 📊 Password Comparison
- Side-by-side comparison of two passwords
- Winner declared with entropy difference
- Detailed rule comparison

### 6. 📚 Learn Security
- Password fundamentals
- Hashing & salting education
- Attack type explanations
- Best practices
- Entropy guide with real examples

### 7. 📋 History & Reports
- Session history table
- Generate + download plain-text security report
- Clear history

---

## 🧠 Technical Details

### Entropy Formula
```
H = L × log₂(N)
```
Where:
- `H` = entropy in bits
- `L` = password length
- `N` = character set size

### Crack Time Estimation
```
time = (2^H) / (2 × guesses_per_second)
```
Average case assumes guessing half the space before finding the password.

### Attack Types (Educational)
| Attack | Method | Best Against |
|--------|--------|-------------|
| Dictionary | Wordlist lookup | Common passwords |
| Brute Force | All combinations | Short passwords |
| Hybrid | Words + mutations | "Smart" common passwords |

### Character Set Sizes
| Characters | Size |
|-----------|------|
| Digits | 10 |
| Lowercase | 26 |
| Uppercase | 26 |
| Special | 32 |
| Full | 94 |

---

## ⚠️ Legal Disclaimer

This tool is for **educational purposes only**.

- Only test passwords you own
- Never use attack techniques on unauthorized systems
- This tool helps you understand security — not break it

---

## 🎓 Topics Covered (for Viva)

1. **Shannon Entropy** — measuring password unpredictability
2. **SHA-2 Family** — one-way cryptographic hash functions
3. **Salt** — random data added before hashing to prevent rainbow tables
4. **Dictionary Attack** — exploiting predictable password choices
5. **Brute Force** — exhaustive search through all possibilities
6. **Hybrid Attack** — combining wordlist with transformation rules
7. **bcrypt / Argon2** — adaptive hash functions designed for passwords
8. **Defense in Depth** — layered security (strong passwords + 2FA + manager)

---

*Built with Python + Streamlit | Educational Cybersecurity Project*
