from fastapi import APIRouter
from pydantic import BaseModel

from app.services.ml_service import predict_threat
from app.services.alert_service import create_alert


router = APIRouter(
    prefix="/threat",
    tags=["Threat Detection"]
)


class NetworkFlow(BaseModel):
    destination_port: int
    flow_duration: float
    total_fwd_packets: int
    total_backward_packets: int
    total_length_fwd_packets: float
    total_length_bwd_packets: float
    flow_bytes_per_s: float
    flow_packets_per_s: float
    flow_iat_mean: float
    flow_iat_std: float
    fwd_packet_length_mean: float
    bwd_packet_length_mean: float
    packet_length_mean: float
    packet_length_std: float
    syn_flag_count: int
    ack_flag_count: int
    down_up_ratio: float
    average_packet_size: float
    active_mean: float
    idle_mean: float


@router.post("/analyze")
def analyze_network(data: NetworkFlow):

    flow_data = {
        "Destination Port": data.destination_port,
        "Flow Duration": data.flow_duration,
        "Total Fwd Packets": data.total_fwd_packets,
        "Total Backward Packets": data.total_backward_packets,
        "Total Length of Fwd Packets": data.total_length_fwd_packets,
        "Total Length of Bwd Packets": data.total_length_bwd_packets,
        "Flow Bytes/s": data.flow_bytes_per_s,
        "Flow Packets/s": data.flow_packets_per_s,
        "Flow IAT Mean": data.flow_iat_mean,
        "Flow IAT Std": data.flow_iat_std,
        "Fwd Packet Length Mean": data.fwd_packet_length_mean,
        "Bwd Packet Length Mean": data.bwd_packet_length_mean,
        "Packet Length Mean": data.packet_length_mean,
        "Packet Length Std": data.packet_length_std,
        "SYN Flag Count": data.syn_flag_count,
        "ACK Flag Count": data.ack_flag_count,
        "Down/Up Ratio": data.down_up_ratio,
        "Average Packet Size": data.average_packet_size,
        "Active Mean": data.active_mean,
        "Idle Mean": data.idle_mean
    }

    ml_analysis = predict_threat(flow_data)

    threat_detected = (
        ml_analysis["threat_class"] != "BENIGN"
    )

    alert = create_alert(
        flow_data,
        ml_analysis
    )

    return {
        "status": "success",
        "message": "Network flow analyzed successfully",
        "threat_detected": threat_detected,
        "ml_analysis": ml_analysis,
        "alert": alert,
        "flow_data": data.model_dump()
    }
