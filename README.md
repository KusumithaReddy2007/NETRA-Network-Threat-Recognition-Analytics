# NETRA
### Network Threat Recognition and Analytics

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

NETRA is a passive AI-assisted network threat detection platform designed for critical infrastructure. It analyzes network traffic metadata using machine learning and presents security insights through a React dashboard.

## Features
- AI-based network flow classification
- DNS exfiltration evaluation
- TLS and QUIC metadata analysis
- Live traffic monitoring
- Threat alerts and analytics
- Passive-only monitoring

## Technology Stack
- Python, FastAPI, Uvicorn
- React, Vite, JavaScript
- Scikit-learn, NumPy, Pandas
- Docker and Docker Compose

## Evaluation Results
| Metric | Result |
|---|---:|
| Flow accuracy | 99.39% |
| Macro F1 | 96.59% |
| DNS validation accuracy | 85.29% |
| DNS false-positive rate | 29.29% |
| Streaming throughput | 103.79 flows/sec |

These are documented prototype results from specific evaluation scenarios, not production guarantees.

## Run Locally
Backend: `PYTHONPATH=backend uvicorn app.main:app --app-dir backend --port 8000`
Frontend: `cd frontend && npm install && npm run dev`

API documentation: http://127.0.0.1:8000/docs

## Project Status
NETRA is a functional SIH research prototype demonstrating passive traffic ingestion, machine-learning inference, behavioral detection and analyst-facing visualization.

## License
No license has been specified yet.

**NETRA — Detect threats. Understand traffic. Strengthen network security.**
