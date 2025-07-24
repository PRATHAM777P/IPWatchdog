from flask import Flask, render_template_string, request, redirect, url_for, flash
import os
import tempfile
import subprocess
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for flashing messages

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'txt', 'log'}

HTML = '''
<!doctype html>
<title>IPWatchdog Dashboard</title>
<h1>Upload your web server access log</h1>
<form method=post enctype=multipart/form-data>
  <label>Log file:</label> <input type=file name=logfile><br><br>
  <label>Whitelist (optional):</label> <input type=file name=whitelist><br><br>
  <label>Blacklist (optional):</label> <input type=file name=blacklist><br><br>
  <input type=submit value=Upload>
</form>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
{% if suspicious_ip %}
  <h2>Suspicious IP detected: {{ suspicious_ip }}</h2>
  {% if is_blacklisted %}
    <p style="color:red; font-weight:bold;">This IP is on your blacklist!</p>
  {% endif %}
  {% if is_whitelisted %}
    <p style="color:green; font-weight:bold;">This IP is on your whitelist (not flagged as suspicious).</p>
  {% endif %}
{% endif %}
{% if chart_img %}
  <h3>Top 10 IPs by Request Count</h3>
  <img src="data:image/png;base64,{{ chart_img }}"/>
{% endif %}
'''

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_ip_file(file_storage):
    if file_storage:
        return set(line.strip() for line in file_storage.read().decode('utf-8').splitlines() if line.strip())
    return set()

def plot_top_ips(csv_path):
    try:
        df = pd.read_csv(csv_path)
        top_ips = df['IP'].value_counts().head(10)
        plt.figure(figsize=(8,4))
        top_ips.plot(kind='bar', color='skyblue')
        plt.title('Top 10 IPs by Request Count')
        plt.xlabel('IP Address')
        plt.ylabel('Request Count')
        plt.tight_layout()
        buf = BytesIO()
        plt.savefig(buf, format='png')
        plt.close()
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        return img_base64
    except Exception as e:
        return None

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    suspicious_ip = None
    is_whitelisted = False
    is_blacklisted = False
    chart_img = None
    if request.method == 'POST':
        if 'logfile' not in request.files:
            flash('No log file part')
            return redirect(request.url)
        file = request.files['logfile']
        whitelist_file = request.files.get('whitelist')
        blacklist_file = request.files.get('blacklist')
        if file.filename == '':
            flash('No selected log file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            tmp_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(tmp_path)
            whitelist = read_ip_file(whitelist_file)
            blacklist = read_ip_file(blacklist_file)
            # Run dataset_generator.py with the uploaded file
            result = subprocess.run(['python', 'dataset_generator.py', tmp_path], capture_output=True, text=True)
            if result.returncode != 0:
                flash(f'Error in dataset generation: {result.stderr}')
            else:
                # Run build_model.py
                result2 = subprocess.run(['python', 'build_model.py'], capture_output=True, text=True)
                if result2.returncode != 0:
                    flash(f'Error in model building: {result2.stderr}')
                else:
                    # Show result.txt
                    if os.path.exists('result.txt'):
                        with open('result.txt', 'r') as f:
                            suspicious_ip = f.read().strip()
                        if suspicious_ip in whitelist:
                            is_whitelisted = True
                        if suspicious_ip in blacklist:
                            is_blacklisted = True
                        # If whitelisted, do not flag as suspicious
                        if is_whitelisted:
                            suspicious_ip = f'{suspicious_ip} (whitelisted)'
                        elif is_blacklisted:
                            suspicious_ip = f'{suspicious_ip} (blacklisted!)'
                    else:
                        flash('No result found. Please check your log file format.')
                    # Visualization: plot top 10 IPs
                    if os.path.exists('ip_set.csv'):
                        chart_img = plot_top_ips('ip_set.csv')
            os.remove(tmp_path)
        else:
            flash('Invalid file type. Please upload a .txt or .log file.')
    return render_template_string(HTML, suspicious_ip=suspicious_ip, is_whitelisted=is_whitelisted, is_blacklisted=is_blacklisted, chart_img=chart_img)

if __name__ == '__main__':
    app.run(debug=True) 