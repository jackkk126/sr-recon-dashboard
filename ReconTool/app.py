from flask import Flask, request, render_template_string, send_file
import subprocess
import re
import os

app = Flask(__name__)

last_domain = ""

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RECON SECURITY DASHBOARD</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {
    background:#0b0f14;
    color:white;
    font-family:Arial;
    padding:20px;
}

h1, h2 {
    color:#00ff99;
    text-transform:uppercase;
}

input, button {
    padding:12px;
    margin:5px;
    border:none;
}

input {
    width:300px;
}

button {
    background:#00ff99;
    color:black;
    font-weight:bold;
    cursor:pointer;
}

.grid {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:15px;
    margin-top:15px;
}

.box {
    background:#111827;
    padding:15px;
    border-radius:10px;
    height:320px;
    overflow:auto;
    border:1px solid #00ff99;
}

pre {
    color:#9cffd0;
    font-size:13px;
}

canvas {
    background:#111827;
    border-radius:8px;
    padding:10px;
}

.stat {
    font-size:22px;
    color:#00ff99;
    font-weight:bold;
}
</style>
</head>

<body>

<h1>Recon Security Dashboard</h1>

<form method="post">
<input name="domain" placeholder="Enter domain" required>
<button type="submit">START SCAN</button>
<a href="/download"><button type="button">DOWNLOAD REPORT</button></a>
</form>

{% if output %}
<div class="grid">

<div class="box">
<h2>SUMMARY</h2>
<p>{{summary}}</p>
<p>Total Vulnerabilities:</p>
<p class="stat">{{vuln_count}}</p>
</div>

<div class="box">
<h2>OPEN PORTS</h2>
<pre>{{ports}}</pre>
</div>

<div class="box">
<h2>VAPT FINDINGS</h2>
<pre>{{vulns}}</pre>
</div>

<div class="box">
<h2>SECURITY SCORE</h2>
<canvas id="scoreChart"></canvas>
</div>

<div class="box" style="grid-column: span 2;">
<h2>FULL SCAN OUTPUT</h2>
<pre>{{output}}</pre>
</div>

</div>

<script>
const score = {{score}};
new Chart(document.getElementById('scoreChart'), {
    type: 'doughnut',
    data: {
        labels: ['SECURE', 'RISK'],
        datasets: [{
            data: [score, 100-score],
        }]
    }
});
</script>

{% endif %}

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    global last_domain

    summary = ""
    ports = ""
    vulns = ""
    output = ""
    score = 50
    vuln_count = 0

    if request.method == "POST":
        domain = request.form["domain"]
        last_domain = domain

        result = subprocess.getoutput(f"python recon.py {domain}")
        output = result

        for line in result.split("\n"):
            if "Port" in line:
                ports += line + "\n"

            if any(word in line for word in
                   ["Missing", "Exposed", "Login", "risk", "Detected"]):
                vulns += line + "\n"
                vuln_count += 1

            if "Security Score" in line:
                s = re.findall(r'\d+', line)
                if s:
                    score = int(s[0])

        summary = f"Scan completed for {domain}"

    return render_template_string(
        HTML,
        output=output,
        summary=summary,
        ports=ports,
        vulns=vulns,
        score=score,
        vuln_count=vuln_count
    )

@app.route("/download")
def download():
    global last_domain
    if last_domain:
        file = f"report_{last_domain}.html"
        if os.path.exists(file):
            return send_file(file, as_attachment=True)
    return "Report not found."

app.run(debug=True)
