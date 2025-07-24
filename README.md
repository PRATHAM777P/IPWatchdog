# 🛡️ IPWatchdog – Suspicious IP Detection Dashboard

> A web-based machine learning tool to identify suspicious IP addresses from web server access logs using clustering techniques.

---

## 🚀 Project Overview

**IPWatchdog** is a security-focused tool that helps web admins and developers identify potentially harmful or unusual IP addresses from their server logs. It combines a **Flask-based dashboard**, **log parser**, and a **K-Means clustering model** for real-time IP monitoring and reporting.

---

## 🔧 Features

- 📁 Upload web server access logs via the dashboard
- ⚙️ Process logs into structured data
- 🤖 Apply ML clustering to detect suspicious behavior
- 📈 Visualize top IPs by request frequency
- ✅ Support for whitelist & blacklist validation

---

## 🧠 Tech Stack

| Tool          | Purpose                    |
|---------------|----------------------------|
| Python        | Core logic & ML            |
| Flask         | Web interface              |
| Pandas        | Data manipulation          |
| scikit-learn  | Clustering model (KMeans)  |
| Matplotlib    | Chart plotting             |

---

## ⚙️ Prerequisites
- Python 3.x
- Required Python packages:
  - pandas
  - scikit-learn
## 📁 Folder Structure

```

📂 IPWatchdog/
├── app.py                → Flask dashboard
├── dataset\_generator.py  → Log parser
├── build\_model.py        → ML clustering
├── requirements.txt      → Python dependencies
├── result.txt            → Identified suspicious IP (sample)
├── ip\_set.csv            → Preprocessed log data (sample)
└── README.md             → Project overview

````

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/IPWatchdog.git
cd IPWatchdog
pip install -r requirements.txt
````


## 📝 Sample Input Format

Your log file (e.g., `access_log.txt`) should look like this:

```
xxx.xxx.xxx.xxx [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1"
```

---

## 📤 Output

* `ip_set.csv` – Parsed logs
* `result.txt` – Suspicious IP address (example only)
* Visualization: Top 10 IPs by request count

---

## 📜 License

MIT License

---

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.
