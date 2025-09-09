#reports/reporter.py
#supports josn output for reporting

import json
import os
from datetime import datetime

def save_json_report(results, output_dir="output_dir", filename=None):
	"""saves the analysis report as a json output"""
	if not os.path.exists(output_dir):
		os.makedirs(output_dir)
	if not filename:
		timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
		filename = f"report_{timestamp}.json"
	path = os.path.join(output_dir, filename)

	with open(path, "w") as file:
		json.dump(results, file, indent=4)

	print(f"[+]JSON report saved at {path}")
	return path
