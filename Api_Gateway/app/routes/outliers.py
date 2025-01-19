from flask import Blueprint, jsonify
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

outliers_bp = Blueprint('outliers', __name__)

# Fetch outliers from the sigma_alerts table for the last 7 days
@outliers_bp.route('/outliers', methods=['GET'])
@cache.cached(timeout=300)
def get_outliers():
    query = """
    SELECT
        title,
        tactics,
        techniques,
        GROUP_CONCAT(DISTINCT user_id) AS origin_users,
        GROUP_CONCAT(DISTINCT computer_name) AS impacted_computers,
        GROUP_CONCAT(DISTINCT ip_address) AS source_ips,
        MIN(system_time) AS first_seen,
        MAX(system_time) AS last_seen,
        COUNT(*) AS anomaly_count,
        rule_level AS severity,
        risk,
        ml_description
    FROM
        sigma_alerts
    WHERE
        ml_cluster = -1
        AND system_time >= NOW() - INTERVAL 7 DAY
    GROUP BY
        title,
        tactics,
        techniques,
        rule_level,
        risk,
        ml_description
    ORDER BY
        anomaly_count DESC,
        last_seen DESC;
    """
    outliers, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(outliers), status_code

    response = {
        "outliers": outliers,
    }
    return jsonify(response), status_code
