from flask import Blueprint, jsonify, request
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

alerts_bp = Blueprint('alerts', __name__)

# Fetch paginated alerts
@alerts_bp.route('/alerts', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_alerts():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=100, type=int)

    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT *
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    ORDER BY system_time DESC
    LIMIT %s OFFSET %s
    """
    alerts, status_code = fetch_data(query, (per_page, offset))

    if status_code != 200:
        return jsonify(alerts), status_code

    total_query = "SELECT COUNT(*) as total FROM sigma_alerts WHERE system_time >= NOW() - INTERVAL 7 DAY"
    total_records, status_code = fetch_data(total_query)

    if status_code != 200:
        return jsonify(total_records), status_code

    response = {
        "alerts": alerts,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200
