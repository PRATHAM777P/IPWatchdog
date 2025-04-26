# 🚨 IPWatchdog (IP Monitoring & Security)

## 📄 Project Overview
**IPWatchdog** is a machine learning-based security tool that automatically identifies suspicious IP addresses from web server access logs. It uses K-means clustering to analyze access patterns and detect potentially malicious behavior.

---

## ✨ Features
- Automated processing of web server access logs
- Machine learning-based suspicious IP detection
- Pattern analysis using K-means clustering
- Easy-to-use command-line interface

---

## ⚙️ Prerequisites
- Python 3.x
- Required Python packages:
  - pandas
  - scikit-learn

---

## 🏗️ Project Structure
- `dataset_generator.py`: Processes access logs and generates a structured dataset.
- `build_model.py`: Implements the machine learning model to detect suspicious IPs.
- `access_log.txt`: Sample input log file (user provided).
- `ip_set.csv`: Structured dataset generated from access logs.
- `result.txt`: Output file listing suspicious IPs.

---

## 🛡️ Legal and Ethical Disclaimer
This tool is intended for **educational and research purposes only**.  
Please ensure compliance with all applicable laws and regulations regarding data privacy and monitoring. Unauthorized or malicious use of this tool is strictly prohibited.

---

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.

---
