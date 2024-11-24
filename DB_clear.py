import sqlite3

def clear_all_entries(db_path):
    """
    Clears all data from all tables in the SQLite database while retaining the schema and columns.

    Parameters:
        db_path (str): Path to the SQLite database file.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get the list of all tables in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        if not tables:
            print("No tables found in the database.")
            return

        # Iterate through all tables and clear their entries
        for table in tables:
            table_name = table[0]
            cursor.execute(f"DELETE FROM {table_name};")
            print(f"All entries removed from table: {table_name}")

        # Commit the changes
        conn.commit()
        print("All entries have been successfully removed while retaining the schema.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the database connection
        if conn:
            conn.close()

if __name__ == "__main__":
    # Path to your SQLite database file
    database_path = "dns_security.db"

    clear_all_entries(database_path)
