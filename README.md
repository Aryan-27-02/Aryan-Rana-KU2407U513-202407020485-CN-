
# AI-Based DDoS Attack Detection and Network Protection

## Project Overview

This project is an AI-based network intrusion detection prototype
that analyses network traffic and identifies potential DDoS attacks.

It uses a Random Forest machine learning classifier to classify
network flows as Normal or DDoS.

## Core Functionalities

1. Network Traffic Analysis and DDoS Detection
2. Email Alert Notification
3. Five-Parameter PDF Detection Report

## Technologies Used

- Python
- Pandas
- NumPy
- Scikit-learn
- Random Forest
- Streamlit
- Joblib
- ReportLab
- SMTP

## Five Detection Factors

1. High Traffic Volume
2. Multiple Traffic Sources
3. High Packet Rate
4. Unusual Traffic Patterns
5. Service Unavailability

The report displays Not available when the uploaded dataset
does not contain the required measurement.

## Project Structure

AI-Based-DDoS-Detection/
|
|-- dataset/
|-- model/
|-- app.py
|-- train_model.py
|-- config.py
|-- requirements.txt
|-- README.md

## Dataset

The project initially uses the CIC-IDS2017 dataset.

Place the training CSV files inside the dataset folder.

The training script uses BENIGN and DDoS-labelled records.

## Model

Random Forest Classifier

The model is trained and evaluated using a train-test split.

Evaluation metrics:

- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix

## Execution

### 1. Open the Project Folder

Open Command Prompt (CMD) and navigate to the project directory:

```cmd
cd /d "E:\Computer networks\Final Project"
```

### 2. Create a Virtual Environment

```cmd
python -m venv venv
```

### 3. Activate the Virtual Environment

```cmd
venv\Scripts\activate
```

### 4. Install Dependencies

```cmd
pip install -r requirements.txt
```

### 5. Add the Dataset

Place the CIC-IDS2017 CSV dataset inside the `dataset` folder.

### 6. Train the Model

```cmd
python train_model.py
```

The trained model will be saved inside the `model` folder.

### 7. Run the Dashboard

```cmd
streamlit run app.py
```

The dashboard will open in your browser. If it does not open automatically, visit:

`http://localhost:8501`

### 8. Email Alert Configuration (Optional)

To enable email notifications, configure the following environment variables in CMD before starting the dashboard:

```cmd
set EMAIL_SENDER=your_email@gmail.com
set EMAIL_PASSWORD=your_gmail_app_password
set EMAIL_RECEIVER=receiver_email@gmail.com
```

**Note:** Keep your Gmail App Password private.

### Running the Project Again

After the initial setup and model training, use only these commands whenever you want to run the project again:

```cmd
cd /d "E:\Computer networks\Final Project"
venv\Scripts\activate
streamlit run app.py
```

## Project Scope

This is an offline network traffic analysis prototype.
It does not perform live traffic monitoring or automatically
block malicious traffic.
