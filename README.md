# 🛡️ AIDS v2.0 - Advanced Intrusion Detection System (GUI-based)

AIDS (Advanced Intrusion Detection System) v2.0 is a Python-based, real-time, GUI-enabled IDS for monitoring and detecting malicious traffic on your network. Built for **educational and research** purposes, this tool helps detect common network attacks and visualize alerts instantly.

---

## ⚙️ Features

* ✅ Real-time network traffic monitoring via `scapy`
* ✅ GUI Dashboard (built with `tkinter`)
* ✅ SYN Flood Detection (Signature-based)
* ✅ Optional ML-based attack classification (`joblib` model support)
* ✅ Live logging with timestamps
* ✅ Interface-specific packet sniffing (`eth0`, `wlan0`, etc.)
* ✅ Easy-to-use single-file script
* ✅ Works on **Kali Linux**, **Ubuntu**, and other Linux distros

---

## 📁 Requirements

* Python 3.8+
* scapy
* joblib (optional, for ML)
* tkinter (comes with Python)

Install dependencies:

```bash
pip install scapy joblib
```

---

## 🚀 How to Run

1. Clone or download the repo
2. Save your trained model as `ids_model.pkl` (optional)
3. Open terminal in project folder
4. Run the script:

```bash
python aids.py
```

---

## 💻 GUI Overview

* **Start IDS**: Begins sniffing on the configured interface
* **Stop IDS**: Stops real-time monitoring
* **Live Log**: Shows detection logs with timestamps
* **Alerts**: Red flag entries indicate suspicious traffic (e.g. SYN Flood)

---

## 🧪 How to Test IDS

You can simulate basic attacks to test detection logic:

### 🔹 SYN Flood:

```bash
sudo hping3 -S 127.0.0.1 -p 80 --flood
```

### 🔹 Port Scan with Nmap:

```bash
nmap -sS -T4 -p- 127.0.0.1
```

> Replace `127.0.0.1` with your actual IP (`ip a` to find it)

---

## 🚰 Customization

* **Change Network Interface:**

  Edit line in code:

  ```python
  INTERFACE = "eth0"
  ```

* **Using ML Detection:**

  Save your model as `ids_model.pkl`. It must accept input vectors like:

  ```
  [protocol, packet_length, source_port, dest_port]
  ```

---

## 📄 Log File

All logs are stored in:

```
aids_logs.txt
```

Includes timestamps and alerts. Useful for post-analysis.

---

## ⚠️ Disclaimer

This tool is for **educational** and **ethical research** purposes only. Do not deploy on unauthorized systems. Creator holds **no liability** for misuse.

---

## 🤝 Credits

Created by Syed Muhammad Qammar Abbas Zaidi
Cybersecurity Enthusiast | Python Developer
