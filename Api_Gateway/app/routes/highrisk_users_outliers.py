from flask import Blueprint, jsonify
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

highrisk_bp = Blueprint('highrisk', __name__)

# Fetch user origin outlier high risk logs
@highrisk_bp.route('/user_origin_outlier_highrisk', methods=['GET'])
@cache.cached(timeout=300)
def get_user_origin_outlier_highrisk():
    query = """
    WITH UserRiskScores AS (
        SELECT 
            user_id AS user,
            title,
            MAX(risk) AS risk_score,
            MAX(ml_cluster) AS ml_cluster,
            COUNT(DISTINCT tactics) AS unique_tactics_count
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        GROUP BY user_id, title
    ),
    CumulativeRisk AS (
        SELECT
            user,
            COUNT(DISTINCT title) AS unique_title_count,
            SUM(CASE WHEN ml_cluster = -1 THEN risk_score + 25 ELSE risk_score END) AS cumulative_risk_score,
            COUNT(DISTINCT CASE WHEN ml_cluster = -1 THEN title ELSE NULL END) AS unique_outliers,
            SUM(unique_tactics_count) AS unique_tactics_count
        FROM UserRiskScores
        GROUP BY user
    )
    SELECT
        cr.user,
        cr.unique_title_count,
        cr.cumulative_risk_score,
        cr.unique_outliers,
        cr.unique_tactics_count
    FROM CumulativeRisk cr
    WHERE cr.user IN (
        SELECT DISTINCT user_id
        FROM sigma_alerts
        WHERE ml_cluster = -1
          AND system_time >= NOW() - INTERVAL 7 DAY
    )
    ORDER BY cr.user;
    """
    user_origin_outlier_highrisk_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_origin_outlier_highrisk_logs), status_code

    response = {
        "user_origin_outlier_highrisk_logs": user_origin_outlier_highrisk_logs,
    }
    return jsonify(response), status_code

# Fetch user impacted outlier high risk logs
@highrisk_bp.route('/user_impacted_outlier_highrisk', methods=['GET'])
@cache.cached(timeout=300)
def get_user_impacted_outlier_highrisk():
    query = """
    WITH UserRiskScores AS (
        SELECT 
            target_user_name AS user,
            title,
            MAX(risk) AS risk_score,
            MAX(ml_cluster) AS ml_cluster,
            COUNT(DISTINCT tactics) AS unique_tactics_count
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        GROUP BY target_user_name, title
    ),
    CumulativeRisk AS (
        SELECT
            user,
            COUNT(DISTINCT title) AS unique_title_count,
            SUM(CASE WHEN ml_cluster = -1 THEN risk_score + 25 ELSE risk_score END) AS cumulative_risk_score,
            COUNT(DISTINCT CASE WHEN ml_cluster = -1 THEN title ELSE NULL END) AS unique_outliers,
            SUM(unique_tactics_count) AS unique_tactics_count
        FROM UserRiskScores
        GROUP BY user
    )
    SELECT
        cr.user,
        cr.unique_title_count,
        cr.cumulative_risk_score,
        cr.unique_outliers,
        cr.unique_tactics_count
    FROM CumulativeRisk cr
    WHERE cr.user IN (
        SELECT DISTINCT target_user_name
        FROM sigma_alerts
        WHERE ml_cluster = -1
          AND system_time >= NOW() - INTERVAL 7 DAY
    )
    ORDER BY cr.user;
    """
    user_impacted_outlier_highrisk_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_impacted_outlier_highrisk_logs), status_code

    response = {
        "user_impacted_outlier_highrisk_logs": user_impacted_outlier_highrisk_logs,
    }
    return jsonify(response), status_code

# Fetch computer impacted outlier high risk logs
@highrisk_bp.route('/computer_impacted_outlier_highrisk', methods=['GET'])
@cache.cached(timeout=300)
def get_computer_impacted_outlier_highrisk():
    query = """
    WITH ComputerRiskScores AS (
        SELECT 
            computer_name AS computer,
            title,
            MAX(risk) AS risk_score,
            MAX(ml_cluster) AS ml_cluster,
            COUNT(DISTINCT tactics) AS unique_tactics_count
        FROM sigma_alerts
        WHERE system_time >= NOW() - INTERVAL 7 DAY
        GROUP BY computer_name, title
    ),
    CumulativeRisk AS (
        SELECT
            computer,
            COUNT(DISTINCT title) AS unique_title_count,
            SUM(CASE WHEN ml_cluster = -1 THEN risk_score + 25 ELSE risk_score END) AS cumulative_risk_score,
            COUNT(DISTINCT CASE WHEN ml_cluster = -1 THEN title ELSE NULL END) AS unique_outliers,
            SUM(unique_tactics_count) AS unique_tactics_count
        FROM ComputerRiskScores
        GROUP BY computer
    )
    SELECT
        cr.computer,
        cr.unique_title_count,
        cr.cumulative_risk_score,
        cr.unique_outliers,
        cr.unique_tactics_count
    FROM CumulativeRisk cr
    WHERE cr.computer IN (
        SELECT DISTINCT computer_name
        FROM sigma_alerts
        WHERE ml_cluster = -1
          AND system_time >= NOW() - INTERVAL 7 DAY
    )
    ORDER BY cr.computer;
    """
    computer_impacted_outlier_highrisk_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(computer_impacted_outlier_highrisk_logs), status_code

    response = {
        "computer_impacted_outlier_highrisk_logs": computer_impacted_outlier_highrisk_logs,
    }
    return jsonify(response), status_code
