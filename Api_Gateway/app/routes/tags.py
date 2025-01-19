from flask import Blueprint, jsonify
from app.utils.db import fetch_data
from app import cache  # Import the initialized cache object

tags_bp = Blueprint('tags', __name__)

# Fetch tags and their counts for the last 7 days
@tags_bp.route('/tags', methods=['GET'])
@cache.cached(timeout=60)
def get_tags():
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
