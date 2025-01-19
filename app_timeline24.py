from flask import Flask, jsonify, request
from flask_cors import CORS
import mysql.connector.pooling
from mysql.connector import Error
from flask_caching import Cache

app = Flask(__name__)

# Enable CORS for specific origins
CORS(app, resources={r"/api/*": {"origins": "http://172.16.0.75:8080"}})

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

# Create a connection pool
db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=10,
    **db_config
)

def get_db_connection():
    """Get a connection from the pool."""
    try:
        connection = db_pool.get_connection()
        return connection
    except Error as e:
        app.logger.error(f"Error getting connection from pool: {e}")
        return None

def fetch_data(query, params=None):
    """Fetch data from the database using the provided query and parameters."""
    connection = get_db_connection()
    if not connection:
        return {"error": "Database connection failed"}, 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        data = cursor.fetchall()
        return data, 200
    except Error as e:
        app.logger.error(f"Error fetching data: {e}")
        return {"error": f"Error fetching data: {e}"}, 500
    finally:
        if connection:
            connection.close()

# Configure caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Alerts endpoint
@app.route('/api/alerts', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_alerts():
    """Fetch paginated records from the sigma_alerts table."""
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=100, type=int)

    # Validate pagination parameters
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

# Total count endpoint
@app.route('/api/total_count', methods=['GET'])
@cache.cached(timeout=60)
def get_total_count():
    """Fetch total count of events from the sigma_alerts table for the last 7 days."""
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

# Tags endpoint
@app.route('/api/tags', methods=['GET'])
@cache.cached(timeout=60)
def get_tags():
    """Fetch tags and their counts from the sigma_alerts table for the last 7 days."""
    query = """
    SELECT tags, COUNT(*) AS total_count
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    GROUP BY tags
    """
    tags, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(tags), status_code

    response = {
        "tags": tags,
    }
    return jsonify(response), 200

# User origin endpoint
@app.route('/api/user_origin', methods=['GET'])
@cache.cached(timeout=300)
def get_user_origin():
    """Fetch user origin logs with cumulative risk scores from the sigma_alerts table for the last 7 days."""
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

# User impacted endpoint
@app.route('/api/user_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_user_impacted():
    """Fetch user impacted logs with cumulative risk scores from the sigma_alerts table for the last 7 days."""
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

# Computer impacted endpoint
@app.route('/api/computer_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_computer_impacted():
    """Fetch computer impacted logs with cumulative risk scores from the sigma_alerts table for the last 7 days, limited to top 50 computers by unique titles."""
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

# Updated ML outliers title endpoint
@app.route('/api/ml_outliers_title', methods=['GET'])
@cache.cached(timeout=300)
def get_ml_outliers_title():
    """Fetch distinct titles and their details where ml_cluster = -1 from the sigma_alerts table for the last 7 days."""
    query = """
    SELECT
        tactics,
        techniques,
        title AS event_title,
        COALESCE(target_user_name, user_id, 'Unknown') AS impacted_user,
        rule_level AS risk_level,
        ml_cluster,
        COUNT(*) AS event_count,
        COUNT(DISTINCT user_id) AS unique_users,
        COUNT(DISTINCT computer_name) AS unique_computers,
        MAX(system_time) AS last_seen,
        MIN(system_time) AS first_seen
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND ml_cluster = -1
    GROUP BY
        tactics, techniques, title, impacted_user, rule_level, ml_cluster
    ORDER BY
        event_count DESC
    """
    ml_outliers_title, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(ml_outliers_title), status_code

    response = {
        "ml_outliers_title": ml_outliers_title,
    }
    return jsonify(response), status_code

# New endpoint for fetching outliers
@app.route('/api/outliers', methods=['GET'])
@cache.cached(timeout=300)
def get_outliers():
    """Fetch outliers from the sigma_alerts table for the last 7 days."""
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

# User origin timeline endpoint
@app.route('/api/user_origin_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_origin_timeline():
    """Fetch user origin timeline logs for the last 7 days."""
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

# User impacted timeline endpoint
@app.route('/api/user_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_timeline():
    """Fetch user impacted timeline logs for the last 7 days."""
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

# Computer impacted timeline endpoint
@app.route('/api/computer_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_computer_impacted_timeline():
    """Fetch computer impacted timeline logs for the last 7 days."""
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

# User impacted logs endpoint
@app.route('/api/user_impacted_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_logs():
    """Fetch logs for a selected user_impacted and title, including raw column, with pagination."""
    user_impacted = request.args.get('user_impacted')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not user_impacted:
        return jsonify({"error": "user_impacted parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    # Validate pagination parameters
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

# Computer impacted logs endpoint
@app.route('/api/computer_impacted_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_computer_impacted_logs():
    """Fetch logs for a selected computer_name and title, including raw column, with pagination."""
    computer_name = request.args.get('computer_name')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not computer_name:
        return jsonify({"error": "computer_name parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    # Validate pagination parameters
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

# User origin logs endpoint
@app.route('/api/user_origin_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_origin_logs():
    """Fetch logs for a selected user_origin and title, including raw column, with pagination."""
    user_origin = request.args.get('user_origin')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not user_origin:
        return jsonify({"error": "user_origin parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    # Validate pagination parameters
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

if __name__ == '__main__':
    # Run the app on the specified host and port
    app.run(host='172.16.0.75', port=5000, debug=True)
