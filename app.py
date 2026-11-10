from flask import Flask, render_template, request, send_file, redirect
from analyzer import analyze_url
import sqlite3
import csv
import io

app = Flask(__name__)

DATABASE = "scan_history.db"


def init_db():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            score INTEGER,
            result TEXT,
            risk_level TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

@app.route("/export")
def export_history():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    history = conn.execute("""
        SELECT url, domain, score, result, risk_level, scanned_at
        FROM scan_history
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "URL", "Domain", "Risk Score",
        "Detection", "Risk Level", "Scanned At"
    ])

    for item in history:
        writer.writerow([
            item["url"],
            item["domain"],
            item["score"],
            item["result"],
            item["risk_level"],
            item["scanned_at"]
        ])

    memory_file = io.BytesIO()
    memory_file.write(output.getvalue().encode("utf-8-sig"))
    memory_file.seek(0)

    return send_file(
        memory_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name="scan_history.csv"
    )
@app.route("/delete-scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        "DELETE FROM scan_history WHERE id = ?",
        (scan_id,)
    )
    conn.commit()
    conn.close()

    return redirect("/")



@app.route("/clear-history", methods=["POST"])
def clear_history():
    conn = sqlite3.connect(DATABASE)
    conn.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

    return redirect("/")

    
@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)

            if not result.get("error"):
                conn = sqlite3.connect(DATABASE)

                conn.execute("""
                    INSERT INTO scan_history
                    (url, domain, score, result, risk_level)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    result["url"],
                    result["domain"],
                    result["score"],
                    result["result"],
                    result["risk_level"]
                ))

                conn.commit()
                conn.close()

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    history = conn.execute("""
        SELECT * FROM scan_history
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()
    stats = conn.execute("""
        SELECT
            COUNT(*) AS total_scans,
            SUM(CASE WHEN result = 'PHISHING' THEN 1 ELSE 0 END) AS phishing_count,
            SUM(CASE WHEN result = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN result = 'LOW RISK' THEN 1 ELSE 0 END) AS low_risk_count
        FROM scan_history
    """).fetchone()

    conn.close()

    return render_template(
        "index.html",
        result=result,
        scan_history=history,
        stats=stats
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)