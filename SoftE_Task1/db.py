import mysql.connector

conn = mysql.connector.connect(
    host="127.0.0.1",     # or "localhost"
    port=3307,            # <-- specify your custom port
    user="matt",
    password="Savythebird!1",
    database="database_db"
)

print("MySQL Connection Successful!")
conn.close()
