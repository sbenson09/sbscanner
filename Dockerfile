# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy project files into the container working directory
COPY ./ ./

RUN pip install --no-cache-dir -r requirements.txt

# Start the script using the Python
ENTRYPOINT ["python3", "sbscanner.py"]

# Defaults
CMD ["--help"]