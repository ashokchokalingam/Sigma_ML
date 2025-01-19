from flask import Blueprint, jsonify, request
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

logs_bp = Blueprint('logs', __name__)

# Fetch logs for a selected origin user and title (paginated)
@logs_bp.route('/user_origin_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_origin_logs():
    user_origin = request.args.get('user_origin')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not user_origin:
        return jsonify({"error": "user_origin parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT *
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND user_id = %s
    AND title = %s
    ORDER BY system_time DESC
    LIMIT %s OFFSET %s;
    """
    user_origin_logs, status_code = fetch_data(query, (user_origin, title, per_page, offset))

    if status_code != 200:
        return jsonify(user_origin_logs), status_code

    total_query = """
    SELECT COUNT(*) as total FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND user_id = %s
    AND title = %s
    """
    total_records, status_code = fetch_data(total_query, (user_origin, title))

    if status_code != 200:
        return jsonify(total_records), status_code

    response = {
        "user_origin_logs": user_origin_logs,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200

# Fetch logs for a selected impacted user and title (paginated)
@logs_bp.route('/user_impacted_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_logs():
    user_impacted = request.args.get('user_impacted')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not user_impacted:
        return jsonify({"error": "user_impacted parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT *
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND target_user_name = %s
    AND title = %s
    ORDER BY system_time DESC
    LIMIT %s OFFSET %s;
    """
    user_impacted_logs, status_code = fetch_data(query, (user_impacted, title, per_page, offset))

    if status_code != 200:
        return jsonify(user_impacted_logs), status_code

    total_query = """
    SELECT COUNT(*) as total FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND target_user_name = %s
    AND title = %s
    """
    total_records, status_code = fetch_data(total_query, (user_impacted, title))

    if status_code != 200:
        return jsonify(total_records), status_code

    response = {
        "user_impacted_logs": user_impacted_logs,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200

# Fetch logs for a specific computer and title (paginated)
@logs_bp.route('/computer_impacted_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_computer_impacted_logs():
    computer_name = request.args.get('computer_name')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not computer_name:
        return jsonify({"error": "computer_name parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT *
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND computer_name = %s
    AND title = %s
    ORDER BY system_time DESC
    LIMIT %s OFFSET %s;
    """
    computer_impacted_logs, status_code = fetch_data(query, (computer_name, title, per_page, offset))

    if status_code != 200:
        return jsonify(computer_impacted_logs), status_code

    total_query = """
    SELECT COUNT(*) as total FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND computer_name = %s
    AND title = %s
    """
    total_records, status_code = fetch_data(total_query, (computer_name, title))

    if status_code != 200:
        return jsonify(total_records), status_code

    response = {
        "computer_impacted_logs": computer_impacted_logs,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200
