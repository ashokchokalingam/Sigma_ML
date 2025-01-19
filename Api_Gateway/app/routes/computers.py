from flask import Blueprint, jsonify
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

computers_bp = Blueprint('computers', __name__)

# Fetch computer impacted logs with cumulative risk scores
@computers_bp.route('/computer_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_computer_impacted():
    query = """
    SELECT
        computer_name,
        COUNT(DISTINCT title) AS unique_titles,
        SUM(risk_score) AS total_unique_risk_score
    FROM (
        SELECT
            computer_name,
            title,
            MAX(risk) AS risk_score
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        AND computer_name IS NOT NULL
        GROUP BY computer_name, title
    ) AS unique_risks
    GROUP BY computer_name
    ORDER BY total_unique_risk_score DESC
    LIMIT 50;
    """
    computer_impacted_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(computer_impacted_logs), status_code

    response = {
        "computer_impacted_logs": computer_impacted_logs,
    }
    return jsonify(response), status_code
