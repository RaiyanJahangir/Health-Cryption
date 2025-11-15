import sqlite3

# Path to your SQLite database file
db_path = "D:\Projects\Health-Cryption\data\plain_health.db"
table_name = "plain_patients"

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Run the query
cursor.execute(f"SELECT * FROM {table_name};")

# Fetch all rows
rows = cursor.fetchall()

# Optionally, print column names first
column_names = [desc[0] for desc in cursor.description]
print(" | ".join(column_names))
print("-" * 40)

# Print each row
for row in rows:
    print(row)

# Clean up
cursor.close()
conn.close()
