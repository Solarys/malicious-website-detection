
import streamlit as st
import pandas as pd
import joblib

st.title("Malicious Website Detection")
st.write("Демо-додаток для класифікації вебсайтів на шкідливі та нешкідливі.")

model = joblib.load("best_malicious_website_model.pkl")

st.subheader("Завантаження CSV-файлу")
uploaded_file = st.file_uploader("Завантажте CSV з характеристиками вебсайтів", type=["csv"])

if uploaded_file is not None:
    data = pd.read_csv(uploaded_file)

    st.write("Перші рядки завантажених даних:")
    st.dataframe(data.head())

    data.columns = data.columns.str.strip()

    if "Type;;" in data.columns:
        data = data.rename(columns={"Type;;": "TYPE"})

    columns_to_drop = ["TYPE", "URL", "WHOIS_REGDATE", "WHOIS_UPDATED_DATE"]
    X_demo = data.drop(columns=columns_to_drop, errors="ignore")

    predictions = model.predict(X_demo)
    probabilities = model.predict_proba(X_demo)[:, 1]

    result = data.copy()
    result["prediction"] = predictions
    result["malicious_probability"] = probabilities
    result["prediction_label"] = result["prediction"].map({
        0: "Benign",
        1: "Malicious"
    })

    st.write("Результати класифікації:")
    st.dataframe(result)

    st.download_button(
        label="Завантажити результати",
        data=result.to_csv(index=False),
        file_name="predictions.csv",
        mime="text/csv"
    )
else:
    st.info("Завантажте CSV-файл для отримання прогнозу.")
