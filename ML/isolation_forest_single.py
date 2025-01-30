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
from scipy.spatial.distance import euclidean
import psutil  # For monitoring system resources

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

def fetch_data():
    """Fetch data from the sigma_alerts table."""
    connection = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, title, tags, computer_name, user_id, target_user_name, event_id, provider_name
            FROM sigma_alerts
            WHERE title NOT IN ('Failed Logon From Public IP', 'User Logoff Event', 'External Remote SMB Logon from Public IP')
        """)
        data = cursor.fetchall()
        cursor.close()
        return data
    except Error as e:
        logging.error(f"Error fetching data: {e}")
        return []
    finally:
        if connection:
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
    event_ids = [handle_nulls(row[6]) for row in data]
    provider_names = [handle_nulls(row[7]) for row in data]

    # Improved TF-IDF processing (merged title & tags)
    tfidf_vectorizer = TfidfVectorizer(stop_words="english")
    combined_text = [title + " " + tag for title, tag in zip(titles, tags)]
    tfidf_vectors = tfidf_vectorizer.fit_transform(combined_text)

    label_encoder = LabelEncoder()
    computer_name_encoded = label_encoder.fit_transform(computer_names)
    user_id_encoded = label_encoder.fit_transform(user_ids)
    target_user_name_encoded = label_encoder.fit_transform(target_user_names)
    event_id_encoded = label_encoder.fit_transform(event_ids)
    provider_name_encoded = label_encoder.fit_transform(provider_names)

    combined_data = np.hstack((
        tfidf_vectors.toarray(),
        computer_name_encoded.reshape(-1, 1),
        user_id_encoded.reshape(-1, 1),
        target_user_name_encoded.reshape(-1, 1),
        event_id_encoded.reshape(-1, 1),
        provider_name_encoded.reshape(-1, 1)
    ))

    return combined_data

def run_isolation_forest(data_scaled):
    """Train Isolation Forest on the dataset and return anomaly scores."""
    isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    isolation_forest.fit(data_scaled)

    anomaly_scores = isolation_forest.decision_function(data_scaled)
    anomaly_labels = isolation_forest.predict(data_scaled)

    return np.where(anomaly_labels == -1, -1, 0), anomaly_scores

def analyze_anomaly_reason(row, data_scaled, i, normal_sample_mean):
    """Generate a dynamic story-style anomaly description."""
    title, user_id, computer_name, event_id, tags = row[1], row[4], row[3], row[6], row[2]
    target_user = row[5]

    deviations = []

    if euclidean(data_scaled[i], normal_sample_mean) > 0.5:
        deviations.append("This event significantly deviates from normal patterns.")

    if title not in normal_sample_mean:
        deviations.append(f"The event '{title}' is rarely seen in this environment.")

    if user_id not in normal_sample_mean:
        deviations.append(f"The user '{user_id}' has not interacted with this system before.")

    if computer_name not in normal_sample_mean:
        deviations.append(f"The computer '{computer_name}' is not typically accessed by this user.")

    if event_id not in normal_sample_mean:
        deviations.append(f"This event type (Event ID: {event_id}) is unusual for this user.")

    if target_user and target_user not in normal_sample_mean:
        deviations.append(f"The target user '{target_user}' is not commonly linked to this source.")

    # Extract MITRE ATT&CK tactics and techniques
    mitre_tactics = [tactic for tactic in tags.split(",") if tactic.startswith("TA")]
    mitre_techniques = [technique for technique in tags.split(",") if technique.startswith("T") and not technique.startswith("TA")]

    tactic_desc = f"This activity aligns with MITRE ATT&CK tactics: {', '.join(mitre_tactics)}." if mitre_tactics else ""
    technique_desc = f"Techniques involved: {', '.join(mitre_techniques)}." if mitre_techniques else ""

    # Constructing a natural language explanation
    description = f"An anomaly was detected: '{title}' involving user '{user_id}' on '{computer_name}' with event ID {event_id}."
    
    if deviations:
        description += " " + " ".join(deviations)

    if tactic_desc or technique_desc:
        description += f" {tactic_desc} {technique_desc}"

    return description.strip()

def update_cluster_labels_and_descriptions(data, anomaly_labels, anomaly_scores, data_scaled):
    """Update sigma_alerts with the anomaly labels and descriptions."""
    if len(anomaly_labels) != len(data):
        logging.error("Mismatch between processed data and anomaly labels. Aborting update.")
        return

    normal_sample_mean = np.mean(data_scaled[anomaly_labels == 0], axis=0)

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        update_query = """
        UPDATE sigma_alerts
        SET ml_cluster = %s, ml_description = %s
        WHERE id = %s
        """
        update_data = [
            (
                int(anomaly_labels[i]), 
                analyze_anomaly_reason(data[i], data_scaled, i, normal_sample_mean) if anomaly_labels[i] == -1 else "Normal Behavior",
                data[i][0]
            )
            for i in range(len(data))
        ]
        cursor.executemany(update_query, update_data)
        connection.commit()
        logging.info(f"Updated {len(update_data)} records with ML cluster labels and descriptions.")
        cursor.close()
    except Error as e:
        logging.error(f"Error updating database: {e}")
    finally:
        if connection:
            connection.close()

def detect_anomalies():
    """Fetch data, process it, train Isolation Forest, and update the database."""
    data = fetch_data()
    if not data:
        logging.warning("No data found in the database.")
        return

    preprocessed_data = preprocess_data(data)
    data_scaled = StandardScaler().fit_transform(preprocessed_data)

    anomaly_labels, anomaly_scores = run_isolation_forest(data_scaled)
    update_cluster_labels_and_descriptions(data, anomaly_labels, anomaly_scores, data_scaled)

detect_anomalies()
schedule.every(5).minutes.do(detect_anomalies)

while True:
    schedule.run_pending()
    time.sleep(1)
