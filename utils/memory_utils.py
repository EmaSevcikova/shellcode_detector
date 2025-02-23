import subprocess


def capture_snapshot(pid, output_file):
    subprocess.run(["gcore", "-o", output_file, str(pid)], check=True)

