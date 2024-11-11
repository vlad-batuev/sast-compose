import os
import sys
import logging
import argparse
import subprocess
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO)
IS_WIN = sys.platform in ['win32', 'cygwin']


class Worker:
    def __init__(self, input_dir, output_file, username=None, password=None):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.username = username
        self.password = password

    def check_image(self, image):
        """Check if a Docker image exists locally."""
        try:
            subprocess.run(["docker", "image", "inspect", image], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False

    def pull_image(self, image):
        """Pull a Docker image from Docker Hub."""
        logging.info(f"Pulling Docker image: {image}")
        try:
            subprocess.run(["docker", "pull", image], check=True)
            logging.info(f"Successfully pulled {image}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to pull {image}: {e}")

    def docker_login(self):
        """Log in to Docker Hub."""
        if self.username and self.password:
            logging.info("Logging in to Docker Hub...")
            try:
                subprocess.run(["docker", "login", "-u", self.username, "-p", self.password], check=True)
                logging.info("Successfully logged in to Docker Hub.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to log in: {e}")
                sys.exit(1)

    def run_scanners(self):
        scanners = {
            "semgrep": {
                "image": "returntocorp/semgrep",
                "command": ["semgrep", "scan", "--json", "--output=/src/semgrep_output.json"]
            },
            "horusec": {
                "image": "horussecurity/horusec",
                "command": ["horusec", "start", "--project-path=/src", "-o=json"", -O=/src/horusec_output.json", "-D=true"]
            },
            "infer": {
                "image": "facebook/infer",
                "command": ["--output", "/src/infer_output.json"]
            },
            "insider": {
                "image": "insider/insider",
                "command": ["--output", "/src/insider_output.json"]
            },
            "gitleaks": {
                "image": "zricethezav/gitleaks",
                "command": ["--report-path", "/src/gitleaks_output.json"]
            }
        }

        json_files = []

        for name, details in scanners.items():
            # Check if the Docker image exists, if not, pull it
            if not self.check_image(details["image"]):
                self.pull_image(details["image"])

            logging.info(f"Running {name} scanner...")
            command = [
                          "docker", "run", "--rm",
                          "-v", f"{self.input_dir}:/src",
                          "-w", "/src",
                          details["image"]
                      ] + details["command"]

            try:
                subprocess.run(command, check=True)
                json_files.append(f"{name}_output.json")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to run {name}: {e}")

        self.merge_json_files(json_files)

    def merge_json_files(self, json_files):
        merged_data = []

        for json_file in json_files:
            with open(json_file, 'r') as f:
                data = json.load(f)
                merged_data.extend(data)

        with open(self.output_file, 'w') as f:
            json.dump(merged_data, f, indent=4)


def main():
    parser = argparse.ArgumentParser(description='Run SAST scanners and merge JSON outputs.')
    parser.add_argument('-i', '--input_dir', help='Path to the directory containing source code.')
    parser.add_argument('-o', '--output_file', help='Path to the output JSON file.')
    parser.add_argument('-u', '--username', help='Docker Hub username.')
    parser.add_argument('-p', '--password', help='Docker Hub password.')

    args = parser.parse_args()

    worker = Worker(args.input_dir, args.output_file, args.username, args.password)

    # Perform docker login if credentials are provided
    if args.username and args.password:
        worker.docker_login()

    worker.run_scanners()


if __name__ == "__main__":
    main()