import time

def follow_log(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        file.seek(0, 2)  # move to end of file

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue
            yield line
