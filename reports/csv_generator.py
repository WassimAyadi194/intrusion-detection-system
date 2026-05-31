import sqlite3
import csv
from pathlib import Path
from datetime import datetime

from config import DB_NAME
from logs.ids_logger import get_logger

_log = get_logger(__name__)


class CSVReportGenerator:
    """Generates CSV reports from the IDS database tables."""

    def __init__(self, db_path: str = DB_NAME, output_dir: str = "reports"):
        self.db_path = db_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_table(self, table_name: str, filename: str) -> str:
        """Exports a specified table to a CSV file and returns a status message."""
        output_path = self.output_dir / filename
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Verify table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if not cursor.fetchone():
                msg = f"Error: Table '{table_name}' does not exist in {self.db_path}."
                _log.error(msg)
                return msg

            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()

            # Fetch column headers
            columns = [description[0] for description in cursor.description]

            with open(output_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(rows)

            msg = f"Exported {len(rows)} rows from '{table_name}' → {output_path}"
            _log.info(msg)
            return msg

        except sqlite3.Error as e:
            msg = f"Database error exporting {table_name}: {e}"
            _log.error(msg)
            return msg
        except Exception as e:
            msg = f"Error exporting {table_name}: {e}"
            _log.error(msg)
            return msg
        finally:
            if 'conn' in locals() and conn:
                conn.close()

    def generate_alerts_report(self, timestamp: str = None) -> None:
        """Generates the alerts CSV report."""
        if not timestamp:
            timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M")
        self.export_table("alerts", f"alerts_report_{timestamp}.csv")

    def generate_logs_report(self, timestamp: str = None) -> None:
        """Generates the logs CSV report."""
        if not timestamp:
            timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M")
        self.export_table("logs", f"logs_report_{timestamp}.csv")

    def generate_selected(self, tables: list[str], timestamp: str = None) -> list[str]:
        """Generates CSV reports for specific selected tables."""
        if not timestamp:
            timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M")
        _log.info("CSV export started for: %s", ", ".join(tables))
        results = []
        for table in tables:
            res = self.export_table(table, f"{table}_report_{timestamp}.csv")
            results.append(res)
        _log.info("CSV export complete.")
        return results

    def generate_all(self) -> None:
        """Generates all defined reports."""
        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M")
        _log.info("CSV export started — db=%s  out=%s", self.db_path, self.output_dir.absolute())
        self.generate_alerts_report(timestamp)
        self.generate_logs_report(timestamp)
        _log.info("CSV export complete.")


if __name__ == "__main__":
    generator = CSVReportGenerator()
    generator.generate_all()

