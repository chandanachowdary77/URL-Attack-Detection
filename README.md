# Identification Of URL-Based Attacks From IP Data

A cybersecurity project designed to detect malicious URLs and analyze network traffic using Machine Learning and PCAP file analysis. The system identifies suspicious IP activity and helps visualize potential cyber attacks through an interactive dashboard.

---

## Tech Stack

**Frontend**
- React.js

**Backend**
- Flask (Python)

**Database / Authentication**
- Firebase Authentication

**Other Technologies**
- Python
- Machine Learning
- PCAP Packet Analysis

---

## Features

- Detect malicious or suspicious URLs
- Upload and analyze PCAP network traffic files
- Identify suspicious IP addresses and attack patterns
- AI-based explanation of detected attacks
- Interactive dashboard with attack reports
- Visualization of attack results
- Export attack logs for further investigation

---

## Project Workflow

1. Upload PCAP files containing network traffic.
2. Extract packets and preprocess network data.
3. Analyze IP addresses and URL patterns.
4. Apply attack detection logic.
5. Generate analysis results.
6. Display attack reports in the dashboard.

---

## How to Run the Project

### Backend Setup

Install dependencies:


pip install -r requirements.txt


Run the backend server:


python main.py


---

### Frontend Setup

Navigate to frontend folder:


cd frontend


Install dependencies:


npm install


Run the frontend:


npm start


---

## Development Progress

- Backend structure for URL attack detection implemented
- PCAP file upload and traffic analysis module added
- Packet extraction and preprocessing from PCAP files implemented
- IP address analysis for suspicious traffic detection added
- URL-based attack detection logic implemented
- Flask API endpoints created for attack analysis
- Frontend dashboard developed for uploading and analyzing PCAP files
- Attack detection results visualization added to UI
- Project documentation and workflow updated

---

## Future Improvements

- Real-time traffic monitoring
- Advanced ML-based attack classification
- Integration with threat intelligence APIs
- Improved visualization and analytics