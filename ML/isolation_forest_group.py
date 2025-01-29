import os
import logging
import schedule
import time
from datetime import datetime
import mysql.connector
from mysql.connector import Error
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from collections import Counter
import psutil

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",  # Root user
    "password": "sigma",  # Password is sigma
    "database": "sigma_db",
}

# MITRE ATT&CK Tactic Mapping
tactic_map = {
    "initial-access": "Initial Access",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "detection.threat-hunting": "Threat Hunting",
    "execution": "Execution"
}

def fetch_data():
    """Fetch data from the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            select_query = """
            SELECT id, title, tags, computer_name, user_id, target_user_name, event_id, provider_name
            FROM sigma_alerts
            WHERE title NOT IN ('Failed Logon From Public IP', 'User Logoff Event', 'External Remote SMB Logon from Public IP')
            """
            cursor.execute(select_query)
            data = cursor.fetchall()
        return data
    except Error as e:
        logging.error(f"Error fetching data: {e}")
        return []
    finally:
        if connection.is_connected():
            connection.close()

def preprocess_data(data):
    """Preprocess the data for Isolation Forest."""
    def handle_nulls(value):
        return value if value not in (None, " ", "", "N/A", "-") else "unknown"

    titles = [handle_nulls(row[1]) for row in data]
    tags = [handle_nulls(row[2]) for row in data]
    computer_names = [handle_nulls(row[3]) for row in data]
    user_ids = [handle_nulls(row[4]) for row in data]
    target_user_names = [handle_nulls(row[5]) for row in data]

    # Define different grouping strategies
    user_origin = [f"{u}_{c}_{t}_{tag}" for u, c, t, tag in zip(user_ids, computer_names, titles, tags)]  # Group -1
    target_user_impacted = [f"{tu}_{c}_{t}_{tag}" for tu, c, t, tag in zip(target_user_names, computer_names, titles, tags)]  # Group -2
    system_group = [f"{c}_{t}_{tag}" for c, t, tag in zip(computer_names, titles, tags)]  # Group -3

    # TF-IDF for text-based fields
    tfidf_vectorizer = TfidfVectorizer(stop_words="english")
    title_tfidf = tfidf_vectorizer.fit_transform(titles)
    tag_tfidf = tfidf_vectorizer.fit_transform(tags)

    # Label Encoding for categorical features
    label_encoder = LabelEncoder()
    user_origin_encoded = label_encoder.fit_transform(user_origin)
    target_user_impacted_encoded = label_encoder.fit_transform(target_user_impacted)
    system_group_encoded = label_encoder.fit_transform(system_group)
    computer_name_encoded = label_encoder.fit_transform(computer_names)
    user_id_encoded = label_encoder.fit_transform(user_ids)
    target_user_name_encoded = label_encoder.fit_transform(target_user_names)

    # Combine all features for Isolation Forest
    combined_data = np.hstack((
        title_tfidf.toarray(),
        tag_tfidf.toarray(),
        user_origin_encoded.reshape(-1, 1),
        target_user_impacted_encoded.reshape(-1, 1),
        system_group_encoded.reshape(-1, 1),
        computer_name_encoded.reshape(-1, 1),
        user_id_encoded.reshape(-1, 1),
        target_user_name_encoded.reshape(-1, 1)
    ))

    return combined_data, user_origin, target_user_impacted, system_group

def run_isolation_forest(data):
    """Run Isolation Forest on the provided data and return the anomaly scores."""
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)

    isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    isolation_forest.fit(data_scaled)
    anomaly_scores = isolation_forest.decision_function(data_scaled)
    anomaly_labels = isolation_forest.predict(data_scaled)

    anomaly_labels = np.where(anomaly_labels == -1, -1, 0)

    return anomaly_labels

def categorize_event(row, is_anomaly):
    """Generate a detailed ML description dynamically based on anomaly detection and frequency analysis."""
    title = row[1].lower()
    tags = row[2].lower()
    user_id = row[4].lower()

    # Detect the MITRE ATT&CK tactic
    detected_tactic = "Unknown"
    for key, value in tactic_map.items():
        if key in tags:
            detected_tactic = value
            break

    if user_id == "root":
        return f"[HIGH RISK] Root User Detected: {title} (MITRE Tactic: {detected_tactic})"

    return f"{title} (MITRE Tactic: {detected_tactic})"

def update_ml_description(data, anomaly_labels):
    """Update sigma_alerts with ML descriptions only."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            update_query = """
            UPDATE sigma_alerts
            SET ml_description = %s
            WHERE id = %s
            """

            update_data = [
                (categorize_event(data[i], anomaly_labels[i] == -1), data[i][0])
                for i in range(len(data))
            ]

            cursor.executemany(update_query, update_data)
            connection.commit()
            logging.info(f"Updated {len(update_data)} records with ML descriptions.")

    except Error as e:
        logging.error(f"Error updating ML descriptions: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def detect_anomalies():
    """Fetch data, run Isolation Forest, and update ML descriptions with anomaly counts."""
    data = fetch_data()
    if not data:
        logging.warning("No data found in the database.")
        return

    preprocessed_data, _, _, _ = preprocess_data(data)
    anomaly_labels = run_isolation_forest(preprocessed_data)

    # Count anomalies
    count_anomalies = Counter(anomaly_labels)
    total_normal = count_anomalies.get(0, 0)
    total_anomalies = count_anomalies.get(-1, 0)

    logging.info(f"Total Normal Entries (0): {total_normal}")
    logging.info(f"Total Anomalies (-1): {total_anomalies}")

    update_ml_description(data, anomaly_labels)

detect_anomalies()
schedule.every(5).minutes.do(detect_anomalies)

while True:
    schedule.run_pending()
    time.sleep(1)
