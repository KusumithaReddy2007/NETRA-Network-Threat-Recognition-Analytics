import sys
from pathlib import Path


sys.path.append(
    str(
        Path(__file__).resolve()
        .parent
        .parent
        / "backend"
    )
)


from app.services.stream_service import stream_flows


result = stream_flows(
    max_flows=100,
    delay=0
)


print("\nNETRA STREAMING TEST")
print("=" * 70)

print(f"Total flows processed: {result['total_flows']}")
print(f"Threat alerts generated: {result['total_alerts']}")
print(f"Total time: {result['total_time_seconds']} seconds")
print(f"Throughput: {result['flows_per_second']} flows/second")


print("\nFIRST 10 FLOW RESULTS")
print("=" * 70)


for flow_result in result["results"][:10]:

    print(f"\nFlow #{flow_result['flow_number']}")
    print(f"Expected: {flow_result['expected_class']}")
    print(f"Predicted: {flow_result['predicted_class']}")
    print(f"Confidence: {flow_result['confidence']}%")
    print(f"Alert generated: {flow_result['alert_generated']}")

    if flow_result["severity"]:
        print(f"Severity: {flow_result['severity']}")

    print(
        f"Processing time: "
        f"{flow_result['processing_time_ms']} ms"
    )


print("\n" + "=" * 70)
