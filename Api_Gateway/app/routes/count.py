from flask import Blueprint, jsonify
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

count_bp = Blueprint('count', __name__)

# Fetch total count of events for the last 7 days
@count_bp.route('/total_count', methods=['GET'])
@cache.cached(timeout=60)
def get_total_count():
    query = """
    SELECT COUNT(*) AS total_count
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    """
    total_count, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(total_count), status_code

    response = {
        "total_count": total_count[0]["total_count"]
    }
    return jsonify(response), 200
