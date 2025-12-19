Automated SOC 2 Security Controls Compliance Framework (AWS)
Project Overview
This project presents an automated framework for enforcing and monitoring SOC 2 Security controls in AWS cloud environments. The system reduces manual audit effort by continuously evaluating cloud resources and visualizing compliance status in real time.

Research Motivation
SOC 2 compliance audits are traditionally manual, time-consuming, and prone to configuration drift. This work explores automation-driven compliance monitoring using cloud-native services to enable continuous assurance.

SOC 2 Controls Implemented
CC6.1 – Logical and role-based access control
CC6.6 – Protection against unauthorized access (S3, IAM)
CC7.2 – Continuous monitoring and logging
System Architecture
The framework consists of:

Policy-based compliance checks (custom security policies)
Automated evaluation using AWS services
Evidence aggregation and compliance status calculation
Real-time visualization using Streamlit
Dashboard
🔗 Live Streamlit Dashboard:

Technologies Used
AWS (IAM, S3, CloudTrail, CloudWatch, Lambda)
Python
Policy-based security enforcement
Streamlit for visualization
How to Run Locally
pip install -r requirements.txt
streamlit run streamlit/app.py
