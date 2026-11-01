
import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from config import (
    DATASET_DIR,
    MODEL_DIR,
    MODEL_PATH,
    LABEL_COLUMN,
    CANDIDATE_FEATURES
)


def load_dataset():
    """Load all CSV files from the dataset folder."""

    files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))

    if not files:
        raise FileNotFoundError(
            "No CSV dataset found inside the dataset folder."
        )

    dataframes = []

    for file in files:
        print(f"Reading: {os.path.basename(file)}")

        df = pd.read_csv(file, low_memory=False)
        df.columns = df.columns.str.strip()

        dataframes.append(df)

    data = pd.concat(dataframes, ignore_index=True)

    return data


def prepare_dataset(data):
    """Keep only BENIGN and DDoS records."""

    data.columns = data.columns.str.strip()

    if LABEL_COLUMN not in data.columns:
        raise ValueError(
            f"Label column '{LABEL_COLUMN}' was not found. "
            f"Available columns: {list(data.columns)}"
        )

    data[LABEL_COLUMN] = (
        data[LABEL_COLUMN]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    # Keep BENIGN and labels containing DDoS.
    benign = data[LABEL_COLUMN] == "BENIGN"
    ddos = data[LABEL_COLUMN].str.contains("DDOS", na=False)

    data = data[benign | ddos].copy()

    data["target"] = np.where(
        data[LABEL_COLUMN] == "BENIGN",
        0,
        1
    )

    if data["target"].nunique() != 2:
        raise ValueError(
            "Both BENIGN and DDoS records are required. "
            "Check that your dataset contains DDoS-labelled traffic."
        )

    features = [
        feature for feature in CANDIDATE_FEATURES
        if feature in data.columns
    ]

    if len(features) < 3:
        raise ValueError(
            "Not enough supported numerical features were found. "
            "Please check your dataset columns."
        )

    print("\nSelected features:")
    for feature in features:
        print("-", feature)

    X = data[features].copy()

    for column in features:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    X = X.replace([np.inf, -np.inf], np.nan)

    y = data["target"]

    # Remove rows where every selected feature is missing.
    valid_rows = X.notna().any(axis=1)

    X = X.loc[valid_rows]
    y = y.loc[valid_rows]

    if y.nunique() != 2:
        raise ValueError(
            "Both classes must have usable feature values."
        )

    return X, y, features


def train_model():
    """Train, evaluate and save the Random Forest model."""

    print("Loading dataset...")

    data = load_dataset()

    print("\nPreparing dataset...")

    X, y, features = prepare_dataset(data)

    print("\nDataset distribution:")
    print(y.value_counts().rename({
        0: "BENIGN",
        1: "DDoS"
    }))

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    model = Pipeline([
        (
            "imputer",
            SimpleImputer(
                strategy="median",
                keep_empty_features=True
            )
        ),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight="balanced",
                n_jobs=-1
            )
        )
    ])

    print("\nTraining Random Forest model...")

    model.fit(X_train, y_train)

    print("\nEvaluating model...")

    predictions = model.predict(X_test)

    print("\nModel Evaluation")
    print("-------------------------")

    print(
        "Accuracy:",
        round(accuracy_score(y_test, predictions), 4)
    )

    print(
        "Precision:",
        round(
            precision_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "Recall:",
        round(
            recall_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print(
        "F1 Score:",
        round(
            f1_score(
                y_test,
                predictions,
                zero_division=0
            ),
            4
        )
    )

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["BENIGN", "DDoS"],
            zero_division=0
        )
    )

    os.makedirs(MODEL_DIR, exist_ok=True)

    model_data = {
        "model": model,
        "features": features,
        "alert_threshold": 0.05
    }

    joblib.dump(model_data, MODEL_PATH)

    print("\nModel saved successfully!")
    print("Location:", MODEL_PATH)


if __name__ == "__main__":
    train_model()
