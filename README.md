# aws_inspector

Ingest external findings from AWS Inspector into CloudPassage Halo

## Overview

This connector ingests AWS Inspector scan findings of workloads also monitored by a Halo agent.
This is done by mapping the Inspector scan findings into Halo attributes and then creaeting the issues using the Cloudpassage Halo API.
The connector identifies the Halo asset to attach the Inspector findings by matching EC2 instance ID.

The integration utilizes the Cloudpassage SDK and Boto3 SDK to interface with the Cloudpassage API and AWS API respectively.
Once the Inspector scan findings are ingested, they can be viewed in the Issues tab in the Halo portal along with other issues
and filtered using external issue attributes.

## Requirements

* CloudPassage Halo API key (with admin permissions)
* CloudPassage Halo agent installed on target workload
* AWS credentials or role with read permissions to AWS Inspector
* Scheduling system such as crontab
* Python 3.6+ including packages specified in "requirements.txt" if running stand-alone or Docker if running as a container

## Installation

The connector can be either be run on a dedicated instance or on serverless compute enginee.


**Important Note:**
The connector is available as a container image at "halotools/aws_inspector".
Installation is only required if running the integration as a stand-alone Python script.

Skip the following step if running as a container.

```
git clone https://github.com/cloudpassage/aws_inspector.git
pip install -r requirements.txt
```

## Setup

### CloudPassage Halo
* Go to "Edit Group Settings" in the Halo portal and create an API key dedicated to the OpenVAS connector
* Make sure target workloads are being monitored by Halo agents

### AWS Inspector
* Install AWS SSM agent on target workloads
* Create assessment targets
* Create assessment template
* Run scans on target workloads which have Halo agents installed on them



## Configuration

Define the following environment variables on the workload running the Inspector connector:

| Name                | Example                          | Explanation     |
|---------------------|----------------------------------|-----------------|
| HALO_API_KEY        | ayj198p9                         |                 |
| HALO_API_SECRET_KEY | 6ulz0yy85xkxkjq8v9z5rahdm4aj909e |                 |
| HALO_API_HOST            | api.cloudpassage.com        | (Optional) Halo API hostname. Default is api.cloudpassage.com   |
| HALO_CONNECTION_PORT      | 443         |   (Optional) Connection port for Halo API https connection. Default is 443 |  

## Run Connector

Below commands are for running the connector once. Schedulers such as cron can be used to run these commands repeatedly.

Create directories for log and timestamp files.
```
cd aws_inspector
mkdir log
mkdir timestamp
```

### Run stand-alone

Run Once:

```python
python application.py
```

### Run as Container

Be sure to inject environment variables defined above in the Docker run command.
Be sure to mount the "log" and "timestamp" directories using the -v option

```
docker run -t --rm -e HALO_API_KEY=halo_api_key -e HALO_API_SECRET=halo_api_secret halotools/aws_inspector:latest
```
