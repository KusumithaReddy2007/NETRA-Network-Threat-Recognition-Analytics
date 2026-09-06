from collections import Counter

from app.services.stream_service import stream_flows


def generate_analytics(max_flows: int = 100):

    stream_result = stream_flows(
        max_flows=max_flows,
        delay=0
    )

    results = stream_result["results"]
    alerts = stream_result["alerts"]

    total_flows = len(results)

    benign_flows = sum(
        1
        for result in results
        if result["predicted_class"] == "BENIGN"
    )

    threat_flows = total_flows - benign_flows

    threat_percentage = (
        round(
            (threat_flows / total_flows) * 100,
            2
        )
        if total_flows > 0
        else 0
    )

    threat_types = Counter(
        result["predicted_class"]
        for result in results
        if result["predicted_class"] != "BENIGN"
    )

    severity_breakdown = Counter(
        alert["severity"]
        for alert in alerts
    )

    return {
        "total_flows": total_flows,
        "benign_flows": benign_flows,
        "threat_flows": threat_flows,
        "threat_percentage": threat_percentage,
        "threat_types": dict(threat_types),
        "severity_breakdown": dict(
            severity_breakdown
        ),
        "processing": {
            "total_time_seconds":
                stream_result["total_time_seconds"],
            "flows_per_second":
                stream_result["flows_per_second"]
        }
    }
