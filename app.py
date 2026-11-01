
import os
import smtplib
from datetime import datetime
from email.message import EmailMessage
from io import BytesIO

import joblib
import numpy as np
import pandas as pd
import streamlit as st

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet

from config import (
    MODEL_PATH,
    DDOS_ALERT_THRESHOLD,
    SMTP_SERVER,
    SMTP_PORT,
    EMAIL_SENDER,
    EMAIL_PASSWORD,
    EMAIL_RECEIVER
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AI-Based DDoS Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI-Based DDoS Attack Detection")
st.write(
    "An AI-powered network traffic analysis system "
    "using a Random Forest classifier."
)


# --------------------------------------------------
# LOAD TRAINED MODEL
# --------------------------------------------------

@st.cache_resource
def load_model():
    if not os.path.exists(MODEL_PATH):
        return None

    return joblib.load(MODEL_PATH)


model_data = load_model()


# --------------------------------------------------
# NETWORK TRAFFIC ANALYSIS
# --------------------------------------------------

def analyse_traffic(data, model_data):
    """Classify uploaded network flows."""

    data.columns = data.columns.str.strip()

    model = model_data["model"]
    features = model_data["features"]

    missing_features = [
        feature for feature in features
        if feature not in data.columns
    ]

    if missing_features:
        raise ValueError(
            "The uploaded CSV is missing model features: "
            + ", ".join(missing_features)
        )

    X = data[features].copy()

    for column in features:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    X = X.replace([np.inf, -np.inf], np.nan)

    if X.isna().all(axis=1).any():
        invalid_count = int(X.isna().all(axis=1).sum())

        raise ValueError(
            f"{invalid_count} rows have no usable model features. "
            "Please upload a compatible traffic CSV."
        )

    predictions = model.predict(X)

    ddos_count = int(np.sum(predictions == 1))
    total_flows = len(predictions)

    ddos_percentage = (
        ddos_count / total_flows
    ) * 100

    threshold = (
        model_data.get(
            "alert_threshold",
            DDOS_ALERT_THRESHOLD
        )
    )

    if ddos_percentage >= threshold * 100:
        status = "DDoS Attack Detected"
    else:
        status = "Normal Traffic"

    return {
        "status": status,
        "total_flows": total_flows,
        "ddos_flows": ddos_count,
        "normal_flows": total_flows - ddos_count,
        "ddos_percentage": ddos_percentage
    }


# --------------------------------------------------
# FIVE DETECTION FACTORS
# --------------------------------------------------

def get_detection_factors(data):
    """Calculate only measurements supported by the CSV."""

    data.columns = data.columns.str.strip()

    factors = {}

    # 1. Traffic Volume
    byte_columns = [
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets"
    ]

    available_byte_columns = [
        col for col in byte_columns
        if col in data.columns
    ]

    if available_byte_columns:
        total_bytes = 0

        for col in available_byte_columns:
            values = pd.to_numeric(
                data[col],
                errors="coerce"
            ).fillna(0)

            total_bytes += values.sum()

        factors["High Traffic Volume"] = (
            f"{total_bytes:,.0f} bytes (measured total)"
        )

    elif "Flow Bytes/s" in data.columns:
        values = pd.to_numeric(
            data["Flow Bytes/s"],
            errors="coerce"
        ).replace([np.inf, -np.inf], np.nan)

        factors["High Traffic Volume"] = (
            f"Average {values.mean():,.2f} bytes/second"
            if values.notna().any()
            else "Not available"
        )

    else:
        factors["High Traffic Volume"] = "Not available"

    # 2. Multiple Traffic Sources
    source_column = next(
        (
            col for col in ["Source IP", "Src IP", "src_ip"]
            if col in data.columns
        ),
        None
    )

    if source_column:
        unique_sources = data[source_column].nunique()

        factors["Multiple Traffic Sources"] = (
            f"{unique_sources} unique source IP addresses"
        )
    else:
        factors["Multiple Traffic Sources"] = "Not available"

    # 3. High Packet Rate
    if "Flow Packets/s" in data.columns:
        values = pd.to_numeric(
            data["Flow Packets/s"],
            errors="coerce"
        ).replace([np.inf, -np.inf], np.nan)

        factors["High Packet Rate"] = (
            f"Average {values.mean():,.2f} packets/second"
            if values.notna().any()
            else "Not available"
        )
    else:
        factors["High Packet Rate"] = "Not available"

    # 4. Unusual Traffic Patterns
    pattern_parts = []

    if "SYN Flag Count" in data.columns:
        syn_values = pd.to_numeric(
            data["SYN Flag Count"],
            errors="coerce"
        )

        if syn_values.notna().any():
            pattern_parts.append(
                f"Average SYN flag count: "
                f"{syn_values.mean():.2f}"
            )

    if "Average Packet Size" in data.columns:
        size_values = pd.to_numeric(
            data["Average Packet Size"],
            errors="coerce"
        )

        if size_values.notna().any():
            pattern_parts.append(
                f"Average packet size: "
                f"{size_values.mean():.2f} bytes"
            )

    factors["Unusual Traffic Patterns"] = (
        "; ".join(pattern_parts)
        if pattern_parts
        else "Not available"
    )

    # 5. Service Unavailability
    availability_columns = [
        "Response Time",
        "response_time",
        "Connection Failures",
        "Failed Connections"
    ]

    available_columns = [
        col for col in availability_columns
        if col in data.columns
    ]

    if available_columns:
        col = available_columns[0]

        values = pd.to_numeric(
            data[col],
            errors="coerce"
        )

        factors["Service Unavailability"] = (
            f"Average {col}: {values.mean():.2f}"
            if values.notna().any()
            else "Not available"
        )
    else:
        factors["Service Unavailability"] = (
            "Not available in the uploaded dataset"
        )

    return factors


# --------------------------------------------------
# EMAIL ALERT
# --------------------------------------------------

def send_email_alert(result, factors):
    """Send an email alert using configured SMTP details."""

    if not all([
        EMAIL_SENDER,
        EMAIL_PASSWORD,
        EMAIL_RECEIVER
    ]):
        raise ValueError(
            "Email settings are missing. "
            "Configure EMAIL_SENDER, EMAIL_PASSWORD "
            "and EMAIL_RECEIVER first."
        )

    message = EmailMessage()

    message["Subject"] = "DDoS Attack Detection Alert"
    message["From"] = EMAIL_SENDER
    message["To"] = EMAIL_RECEIVER

    factor_text = "\n".join(
        f"{name}: {value}"
        for name, value in factors.items()
    )

    message.set_content(
        f"""
DDoS Detection Alert

Detection Status: {result['status']}
Analysis Time: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}

Total Flows: {result['total_flows']}
DDoS Flows: {result['ddos_flows']}
DDoS Prediction Rate: {result['ddos_percentage']:.2f}%

Five Detection Factors:
{factor_text}

This is an automated alert from the
AI-Based DDoS Attack Detection System.
"""
    )

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()

        server.login(
            EMAIL_SENDER,
            EMAIL_PASSWORD
        )

        server.send_message(message)


# --------------------------------------------------
# PDF REPORT
# --------------------------------------------------

def generate_pdf_report(result, factors):
    """Generate a downloadable PDF detection report."""

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI-Based DDoS Attack Detection Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"Analysis Date: "
            f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"<b>Detection Result:</b> {result['status']}",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"Total Flows Analysed: {result['total_flows']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"DDoS Flows: {result['ddos_flows']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Normal Flows: {result['normal_flows']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"DDoS Prediction Rate: "
            f"{result['ddos_percentage']:.2f}%",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Five DDoS Detection Factors",
            styles["Heading2"]
        )
    )

    table_data = [
        ["Detection Factor", "Measured Value"]
    ]

    for name, value in factors.items():
        table_data.append([name, value])

    table = Table(
        table_data,
        colWidths=[190, 300]
    )

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
        ])
    )

    content.append(table)

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Note: The five factors are supporting indicators. "
            "The final classification is produced by the trained "
            "machine-learning model. A missing measurement is "
            "shown as Not available.",
            styles["Normal"]
        )
    )

    document.build(content)

    buffer.seek(0)

    return buffer


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if model_data is None:

    st.error(
        "Trained model not found. "
        "Please run train_model.py before starting the dashboard."
    )

    st.stop()


st.subheader("Upload Network Traffic Dataset")

uploaded_file = st.file_uploader(
    "Upload a compatible network traffic CSV file",
    type=["csv"]
)

if uploaded_file is not None:

    if st.button("Analyse Network Traffic"):

        try:
            with st.spinner("Analysing network traffic..."):

                traffic_data = pd.read_csv(
                    uploaded_file,
                    low_memory=False
                )

                result = analyse_traffic(
                    traffic_data,
                    model_data
                )

                factors = get_detection_factors(
                    traffic_data
                )

                st.session_state["result"] = result
                st.session_state["factors"] = factors

                st.session_state["analysis_time"] = (
                    datetime.now().strftime(
                        "%d-%m-%Y %H:%M:%S"
                    )
                )

        except Exception as error:
            st.error(f"Analysis failed: {error}")


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

if "result" in st.session_state:

    result = st.session_state["result"]
    factors = st.session_state["factors"]

    st.divider()

    st.subheader("Detection Result")

    if result["status"] == "DDoS Attack Detected":
        st.error("DDoS Attack Detected")
    else:
        st.success("Normal Traffic")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Flows",
        f"{result['total_flows']:,}"
    )

    col2.metric(
        "DDoS Flows",
        f"{result['ddos_flows']:,}"
    )

    col3.metric(
        "DDoS Prediction Rate",
        f"{result['ddos_percentage']:.2f}%"
    )

    st.subheader("Five Detection Factors")

    for name, value in factors.items():
        st.write(f"**{name}:** {value}")

    # Generate PDF
    pdf_file = generate_pdf_report(
        result,
        factors
    )

    st.download_button(
        label="Download PDF Report",
        data=pdf_file,
        file_name="DDoS_Detection_Report.pdf",
        mime="application/pdf"
    )

    # Send email only when DDoS is detected.
    if result["status"] == "DDoS Attack Detected":

        if st.button("Send DDoS Email Alert"):

            try:
                send_email_alert(
                    result,
                    factors
                )

                st.success(
                    "DDoS alert email sent successfully!"
                )

            except Exception as error:
                st.error(
                    f"Email could not be sent: {error}"
                )

    else:
        st.info(
            "No email alert is required because "
            "the uploaded traffic was classified as normal."
        )
