import mysql.connector.pooling
from mysql.connector import Error
from flask import current_app

db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=10,
    **db_config
)

def get_db_connection():
    try:
        connection = db_pool.get_connection()
        return connection
    except Error as e:
        current_app.logger.error(f"Error getting connection from pool: {e}")
        return None

def fetch_data(query, params=None):
    connection = get_db_connection()
    if not connection:
        return {"error": "Database connection failed"}, 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        data = cursor.fetchall()
        return data, 200
    except Error as e:
        current_app.logger.error(f"Error fetching data: {e}")
        return {"error": f"Error fetching data: {e}"}, 500
    finally:
        if connection:
            connection.close()
