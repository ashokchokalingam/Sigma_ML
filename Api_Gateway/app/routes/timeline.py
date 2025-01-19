from flask import Blueprint, jsonify, request
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

timeline_bp = Blueprint('timeline', __name__)

# Fetch user origin timeline logs for a specific user
@timeline_bp.route('/user_origin_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_origin_timeline():
    user_origin = request.args.get('user_origin')
    if not user_origin:
        return jsonify({"error": "user_origin parameter is required"}), 400

    query = """
    SELECT
        user_id AS user_origin,
        title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND user_id = %s
    GROUP BY
        user_id, title, tags, description, rule_level
    ORDER BY
        title;
    """
    user_origin_timeline, status_code = fetch_data(query, (user_origin,))

    if status_code != 200:
        return jsonify(user_origin_timeline), status_code

    response = {
        "user_origin_timeline": user_origin_timeline,
    }
    return jsonify(response), status_code

# Fetch user impacted timeline logs for a specific impacted user
@timeline_bp.route('/user_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_timeline():
    user_impacted = request.args.get('user_impacted')
    if not user_impacted:
        return jsonify({"error": "user_impacted parameter is required"}), 400

    query = """
    SELECT
        target_user_name AS user_impacted,
        title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND target_user_name = %s
    GROUP BY
        target_user_name, title, tags, description, rule_level
    ORDER BY
        title;
    """
    user_impacted_timeline, status_code = fetch_data(query, (user_impacted,))

    if status_code != 200:
        return jsonify(user_impacted_timeline), status_code

    response = {
        "user_impacted_timeline": user_impacted_timeline,
    }
    return jsonify(response), status_code

# Fetch computer impacted timeline logs for a specific computer
@timeline_bp.route('/computer_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_computer_impacted_timeline():
    computer_name = request.args.get('computer_name')
    if not computer_name:
        return jsonify({"error": "computer_name parameter is required"}), 400

    query = """
    SELECT
        computer_name, title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND computer_name = %s
    GROUP BY
        computer_name, title, tags, description, rule_level
    ORDER BY
        title;
    """
    computer_impacted_timeline, status_code = fetch_data(query, (computer_name,))

    if status_code != 200:
        return jsonify(computer_impacted_timeline), status_code

    response = {
        "computer_impacted_timeline": computer_impacted_timeline,
    }
    return jsonify(response), status_code
