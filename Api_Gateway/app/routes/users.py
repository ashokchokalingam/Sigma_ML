from flask import Blueprint, jsonify, request
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

users_bp = Blueprint('users', __name__)

# Fetch user origin logs with cumulative risk scores
@users_bp.route('/user_origin', methods=['GET'])
@cache.cached(timeout=300)
def get_user_origin():
    query = """
    SELECT
        user_id AS user_origin,
        COUNT(DISTINCT title) AS unique_titles,
        SUM(risk_score) AS total_unique_risk_score
    FROM (
        SELECT
            user_id,
            title,
            MAX(risk) AS risk_score
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        AND user_id IS NOT NULL
        GROUP BY user_id, title
    ) AS unique_risks
    GROUP BY user_id
    ORDER BY total_unique_risk_score DESC
    LIMIT 50;
    """
    user_origin_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_origin_logs), status_code

    response = {
        "user_origin_logs": user_origin_logs,
    }
    return jsonify(response), status_code

# Fetch user impacted logs with cumulative risk scores
@users_bp.route('/user_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_user_impacted():
    query = """
    SELECT
        target_user_name AS user_impacted,
        COUNT(DISTINCT title) AS unique_titles,
        SUM(risk_score) AS total_unique_risk_score
    FROM (
        SELECT
            target_user_name,
            title,
            MAX(risk) AS risk_score
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        AND target_user_name IS NOT NULL
        GROUP BY target_user_name, title
    ) AS unique_risks
    GROUP BY target_user_name
    ORDER BY total_unique_risk_score DESC
    LIMIT 50;
    """
    user_impacted_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_impacted_logs), status_code

    response = {
        "user_impacted_logs": user_impacted_logs,
    }
    return jsonify(response), status_code
