# Project-1_Elevate-Labs-
Cyber Threat Intelligence Dashboard
# Project-1_Elevate-Labs-
Cyber Threat Intelligence Dashboard
mkdir cti-dashboard
cd cti-dashboard
git init


python -m venv venv

venv\Scripts\Activate.ps1


pip install flask pymongo requests python-dotenv flask-cors

pip freeze > requirements.txt





cti-dashboard/
├─ app.py
├─ requirements.txt
├─ .env          # DO NOT commit
├─ .gitignore
├─ templates/index.html
├─ static/
└─ README.md






# python
__pycache__/
*.pyc
venv/
.env
instance/
*.sqlite3

VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
MONGODB_URI=your_mongodb_uri_here
FLASK_ENV=development


git add .
git commit -m "Initial project scaffold: CTI dashboard (Flask + MongoDB)"

git remote add origin https://github.com/<yourusername>/cti-dashboard.git
git branch -M main
git push -u origin main



** to run project locally **

git clone https://github.com/<yourusername>/cti-dashboard.git
cd cti-dashboard

# create venv and activate
python -m venv venv
source venv/bin/activate   # or venv\Scripts\Activate.ps1 on Windows

# install deps
pip install -r requirements.txt

# create .env (fill keys)
cp .env.example .env   # (create a .env.example that has var names but no secrets)
# edit .env to add API keys and MONGO URI

# run
python app.py
# or
flask run

Create a develop branch and keep main 

git checkout -b develop

git push -u origin develop


## Template 
# CTI Dashboard (Flask + MongoDB)

## Quick start
1. Clone repo
2. Create venv and install
3. Add `.env` with API keys and MONGO URI
4. Run `python app.py` and open http://127.0.0.1:5000

## Environment variables
- VIRUSTOTAL_API_KEY
- ABUSEIPDB_API_KEY
- MONGODB_URI

## Development notes
- Use MongoDB Atlas for easy setup.
- Do not commit `.env`.


** Flask Backend


---

## 5️⃣ `app.py`
This is the full working Flask backend.  
You can run this directly after setting `.env` and MongoDB.

```python
import os
import time
import csv
from io import StringIO
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import requests

# Load .env configuration
load_dotenv()

# Fetch API keys and config
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")

app = Flask(__name__)
CORS(app)

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client['ctidb']
lookups = db['lookups']

# API headers
HEADERS_VT = {"x-apikey": VT_KEY}
HEADERS_ABUSE = {"Key": ABUSE_KEY, "Accept": "application/json"}

# Helper: query VirusTotal
def query_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers=HEADERS_VT, timeout=10)
    return r.json() if r.ok else {"error": r.text}

# Helper: query AbuseIPDB
def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=10)
    return r.json() if r.ok else {"error": r.text}

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Lookup endpoint
@app.route('/api/lookup', methods=['POST'])
def lookup():
    data = request.json
    subject = data.get('subject')
    typ = data.get('type', 'ip')

    record = {"subject": subject, "type": typ, "timestamp": time.time(), "results": {}}

    try:
        if typ == 'ip':
            vt = query_virustotal_ip(subject)
            abuse = query_abuseipdb(subject)
            record['results']['virustotal'] = vt
            record['results']['abuseipdb'] = abuse
            vt_malicious = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
            record['threat_score'] = (vt_malicious * 5) + abuse_score
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{subject}"
            vt = requests.get(url, headers=HEADERS_VT).json()
            record['results']['virustotal'] = vt
            record['threat_score'] = 0
    except Exception as e:
        record['results']['error'] = str(e)

    record['tags'] = []
    inserted = lookups.insert_one(record)
    record['_id'] = str(inserted.inserted_id)
    return jsonify(record)

# Recent lookups
@app.route('/api/recent', methods=['GET'])
def recent():
    docs = list(lookups.find().sort("timestamp", -1).limit(100))
    for d in docs:
        d['_id'] = str(d['_id'])
    return jsonify(docs)

# Add tags
@app.route('/api/tag', methods=['POST'])
def add_tag():
    from bson.objectid import ObjectId
    data = request.json
    _id = data.get('_id')
    tag = data.get('tag')
    if not (_id and tag):
        return jsonify({"error": "Missing data"}), 400
    lookups.update_one({"_id": ObjectId(_id)}, {"$addToSet": {"tags": tag}})
    return jsonify({"ok": True})

# Export CSV
@app.route('/api/export', methods=['GET'])
def export_csv():
    docs = list(lookups.find().sort("timestamp", -1))
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["timestamp", "subject", "type", "threat_score", "tags"])
    for d in docs:
        cw.writerow([d.get('timestamp'), d.get('subject'), d.get('type'), d.get('threat_score'), ",".join(d.get('tags', []))])
    si.seek(0)
    return send_file(StringIO(si.getvalue()), mimetype='text/csv', as_attachment=True, download_name='cti_export.csv')

if __name__ == '__main__':
    app.run(debug=True)

# Copy this file to .env and fill your real API keys

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# MongoDB connection
# For local: mongodb://localhost:27017/
# For Atlas (recommended): mongodb+srv://<username>:<password>@cluster0.mongodb.net/ctidb
MONGODB_URI=your_mongodb_uri_here

# Flask environment
FLASK_ENV=development


# Copy this file to .env and fill your real API keys
# Copy this file to .env and fill your real API keys

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# MongoDB connection
# For local: mongodb://localhost:27017/
# For Atlas (recommended): mongodb+srv://<username>:<password>@cluster0.mongodb.net/ctidb
MONGODB_URI=your_mongodb_uri_here

# Flask environment
FLASK_ENV=development




# Templates.html 

<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>CTI Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"/>
</head>
<body class="p-4">
  <div class="container">
    <h1>🛡️ Cyber Threat Intelligence Dashboard</h1>

    <div class="my-3 input-group">
      <input id="subject" class="form-control" placeholder="Enter IP or domain"/>
      <select id="type" class="form-select">
        <option value="ip" selected>IP</option>
        <option value="domain">Domain</option>
      </select>
      <button id="lookupBtn" class="btn btn-primary">Lookup</button>
    </div>

    <pre id="result" class="bg-light p-3 rounded border" style="min-height:100px;"></pre>

    <h3>📊 Recent Lookups</h3>
    <canvas id="trendChart" height="100"></canvas>

    <table class="table table-striped mt-3" id="recentTable">
      <thead><tr><th>Time</th><th>Subject</th><th>Score</th><th>Tags</th><th>Action</th></tr></thead>
      <tbody></tbody>
    </table>

    <button id="exportBtn" class="btn btn-outline-secondary">Export CSV</button>
  </div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
async function refresh(){
  const res = await fetch('/api/recent');
  const data = await res.json();
  const tbody = document.querySelector('#recentTable tbody');
  tbody.innerHTML = '';
  const points = [];

  data.reverse().forEach(d=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${new Date(d.timestamp*1000).toLocaleString()}</td>
                    <td>${d.subject}</td>
                    <td>${d.threat_score||0}</td>
                    <td>${(d.tags||[]).join(', ')}</td>
                    <td><button class="btn btn-sm btn-outline-primary" onclick="addTag('${d._id}')">Tag</button></td>`;
    tbody.appendChild(tr);
    points.push({x: new Date(d.timestamp*1000), y: d.threat_score||0});
  });

  const ctx = document.getElementById('trendChart').getContext('2d');
  if(window.myChart) window.myChart.destroy();
  window.myChart = new Chart(ctx, {
    type: 'line',
    data: { datasets: [{ label: 'Threat Score', data: points }] },
    options: { scales: { x: { type: 'time', time: { unit: 'minute' } } } }
  });
}

async function addTag(id){
  const tag = prompt('Enter a tag');
  if(!tag) return;
  await fetch('/api/tag', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({_id:id, tag})});
  refresh();
}

document.getElementById('lookupBtn').addEventListener('click', async ()=>{
  const subject = document.getElementById('subject').value.trim();
  const type = document.getElementById('type').value;
  if(!subject) return alert('Enter IP or domain');
  document.getElementById('result').innerText = 'Fetching data...';
  const r = await fetch('/api/lookup', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({subject, type})
  });
  const json = await r.json();
  document.getElementById('result').innerText = JSON.stringify(json.results, null, 2);
  refresh();
});

document.getElementById('exportBtn').addEventListener('click', ()=> window.location='/api/export');
refresh();
</script>
</body>
</html>


*Final Setup*

Paste these files in your cti-dashboard folder.

Create .env by copying .env.example and adding real keys.

Activate venv → install → run python app.py.

git add .
git commit -m "Initial CTI Dashboard setup"
git branch -M main
git remote add origin https://github.com/<yourusername>/cti-dashboard.git
git push -u origin main

