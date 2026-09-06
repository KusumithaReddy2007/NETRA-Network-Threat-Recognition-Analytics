from fastapi import APIRouter, Query

from app.services.analytics_service import generate_analytics


router = APIRouter(
    prefix="/analytics",
    tags=["Analytics"]
)


@router.get("/summary")
def analytics_summary(
    max_flows: int = Query(
        default=100,
        ge=1,
        le=1000
    )
):

    analytics = generate_analytics(
        max_flows=max_flows
    )

    return {
        "status": "success",
        "message":
            "NETRA analytics generated successfully",
        "analytics": analytics
    }
