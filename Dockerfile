# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variables
ENV CLOUDFLARE_API_TOKEN your_cloudflare_api_token
ENV CLOUDFLARE_ZONE_ID your_cloudflare_zone_id
ENV IPQS_API_KEY your_ipqs_api_key

# Run ip_enricher_cli.py when the container launches
ENTRYPOINT ["python", "ip_enricher_cli.py"]
