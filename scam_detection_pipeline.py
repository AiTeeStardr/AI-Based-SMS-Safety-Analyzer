"""
=============================================================================
Project: AI Scam & Phishing SMS Detector (ระบบตรวจจับข้อความมิจฉาชีพและหลอกลวง)
Subject: Machine Learning (07_Natural_Language_Processing + 02_Supervised_Learning)
Dataset: thai_scam_sms_dataset.csv
=============================================================================
"""

import os
import re
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)

# ---------------------------------------------------------------------------
# 1. โหลดข้อมูล
# ---------------------------------------------------------------------------
def load_data(filepath="thai_scam_sms_dataset.csv"):
    print("=" * 65)
    print(" 1. โหลดชุดข้อมูลข้อความภาษาไทย (Data Loading)...")
    print("=" * 65)
    df = pd.read_csv(filepath)
    print(f"- จำนวนข้อมูลทั้งหมด: {len(df)} ข้อความ")
    print("\n[สัดส่วนข้อมูล]:")
    print(df['category'].value_counts())
    return df

# ---------------------------------------------------------------------------
# 2. การเตรียมข้อความ (Text Preprocessing)
# ---------------------------------------------------------------------------
def clean_text(text):
    text = str(text).strip()
    return text

# ---------------------------------------------------------------------------
# 3. ฝึกสอนและเปรียบเทียบโมเดล NLP
# ---------------------------------------------------------------------------
def train_nlp_models(df, output_dir="charts"):
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "=" * 65)
    print(" 2. การแปลงข้อความเป็นเวกเตอร์ (TF-IDF Feature Extraction)...")
    print("=" * 65)
    
    X = df['text']
    y = df['label']
    
    # แบ่งข้อมูล 80% Train, 20% Test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # ใช้ TF-IDF Vectorizer (Word + Sub-word N-grams สำหรับภาษาไทย)
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3),
        min_df=2,
        sublinear_tf=True
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    print(f"- ขนาด Vocabulary Matrix: {X_train_vec.shape[1]} ฟีเจอร์คำศัพท์")
    
    # 4 โมเดลหลักของ NLP
    models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(random_state=42, C=2.0),
        "Support Vector Machine (LinearSVC)": CalibratedClassifierCV(LinearSVC(random_state=42, dual=False)),
        "Random Forest Classifier": RandomForestClassifier(random_state=42, n_estimators=150)
    }
    
    print("\n" + "=" * 65)
    print(" 3. ฝึกสอนและประเมินผลเปรียบเทียบโมเดล NLP...")
    print("=" * 65)
    
    results = []
    trained_models = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.flatten()
    
    plt_roc = plt.figure(figsize=(9, 7))
    
    for idx, (name, model) in enumerate(models.items()):
        model.fit(X_train_vec, y_train)
        trained_models[name] = model
        
        y_pred = model.predict(X_test_vec)
        y_prob = model.predict_proba(X_test_vec)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob)
        cv_score = cross_val_score(model, X_train_vec, y_train, cv=cv, scoring='accuracy').mean()
        
        results.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": auc,
            "5-Fold CV": cv_score
        })
        
        # วาด Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=axes[idx],
                    xticklabels=['ข้อความปกติ (0)', 'มิจฉาชีพ (1)'],
                    yticklabels=['ข้อความปกติ (0)', 'มิจฉาชีพ (1)'])
        axes[idx].set_title(f"{name}\nAcc: {acc*100:.1f}% | Rec: {rec*100:.1f}%", fontweight='bold')
        axes[idx].set_xlabel('Predicted')
        axes[idx].set_ylabel('Actual')
        
        # วาด ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        plt.figure(plt_roc.number)
        plt.plot(fpr, tpr, label=f"{name} (AUC = {auc:.3f})", linewidth=2)
    
    # บันทึกรูป Confusion Matrix
    fig.tight_layout()
    cm_path = os.path.join(output_dir, "scam_confusion_matrices.png")
    fig.savefig(cm_path, dpi=300)
    plt.close(fig)
    print(f"บันทึกกราฟ: {cm_path}")
    
    # บันทึกรูป ROC Curves
    plt.figure(plt_roc.number)
    plt.plot([0, 1], [0, 1], 'k--', label='Random Chance (0.50)')
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate (Recall)', fontsize=12)
    plt.title('ROC Curve Comparison - Scam & Phishing Detection', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    roc_path = os.path.join(output_dir, "scam_roc_curves.png")
    plt.savefig(roc_path, dpi=300)
    plt.close(plt_roc)
    print(f"บันทึกกราฟ: {roc_path}")
    
    # สกัดคำศัพท์ที่เป็นตัวบ่งชี้มิจฉาชีพสูงสุด (Top Scam Keywords from Logistic Regression)
    lr_model = trained_models["Logistic Regression"]
    feature_names = vectorizer.get_feature_names_out()
    coefs = lr_model.coef_[0]
    
    # คำศัพท์ที่ค่าน้ำหนักบวกสูงสุด (มิจฉาชีพ)
    top_scam_idx = np.argsort(coefs)[::-1][:15]
    top_scam_words = [feature_names[i] for i in top_scam_idx]
    top_scam_weights = [coefs[i] for i in top_scam_idx]
    
    plt.figure(figsize=(10, 6))
    plt.barh(top_scam_words[::-1], top_scam_weights[::-1], color='#DC2626')
    plt.title('Top 15 Indicative Keywords for Scam Messages (NLP)', fontsize=14, fontweight='bold')
    plt.xlabel('Log-Odds Coefficient (Scam Influence)', fontsize=12)
    plt.tight_layout()
    kw_path = os.path.join(output_dir, "top_scam_keywords.png")
    plt.savefig(kw_path, dpi=300)
    plt.close()
    print(f"บันทึกกราฟ: {kw_path}")
    
    # สรุปตารางผลลัพธ์
    results_df = pd.DataFrame(results).sort_values(by="F1-Score", ascending=False)
    print("\n" + "=" * 80)
    print(" [ตารางสรุปผลเปรียบเทียบโมเดล NLP Scam Detection Summary] ")
    print("=" * 80)
    print(results_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    print("=" * 80)
    results_df.to_csv("scam_model_evaluation.csv", index=False)
    
    # ส่งออกคำศัพท์และน้ำหนักเป็น JSON เพื่อให้ Web App ใช้งานแบบไม่ต้องพึ่ง Server
    keywords_dict = {feature_names[i]: float(coefs[i]) for i in range(len(feature_names)) if abs(coefs[i]) > 0.3}
    with open("scam_weights.json", "w", encoding="utf-8") as f:
        json.dump({
            "intercept": float(lr_model.intercept_[0]),
            "keywords": keywords_dict
        }, f, ensure_ascii=False, indent=2)
    print("ส่งออกโมเดลน้ำหนักคำศัพท์ลงไฟล์: scam_weights.json เรียบร้อย!")
    
    return vectorizer, trained_models

# ---------------------------------------------------------------------------
# 4. ฟังก์ชันทดสอบทำนายข้อความจริง
# ---------------------------------------------------------------------------
def predict_message(text, vectorizer, model):
    vec = vectorizer.transform([text])
    pred = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0]
    
    print("\n--- ทดสอบข้อความ: ---")
    print(f"ข้อความ: \"{text}\"")
    if pred == 1:
        print(f"[SCAM ALERT] ผลวิเคราะห์: มิจฉาชีพ/หลอกลวง (Scam) | ความมั่นใจ: {prob[1]*100:.2f}%")
    else:
        print(f"[SAFE] ผลวิเคราะห์: ข้อความปกติ ปลอดภัย (Safe) | ความมั่นใจ: {prob[0]*100:.2f}%")
    return pred, prob

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    df = load_data()
    vectorizer, models = train_nlp_models(df)
    
    best_model = models["Multinomial Naive Bayes"]
    
    # ทดสอบตัวอย่าง
    predict_message("Flash Express: พัสดุของคุณตกค้าง ชำระเงินเพิ่ม 20 บาทที่ bit.ly/flash-claim", vectorizer, best_model)
    predict_message("เงินกู้ด่วนทันใจ อนุมัติ 10 นาที ดอกเบี้ย 0.5% ไม่เช็คบูโร ทักไลน์ @fastloan", vectorizer, best_model)
    predict_message("รหัส OTP ของคุณคือ 847291 ใช้ยืนยันการโอนเงิน ห้ามบอกรหัสนี้แก่ผู้อื่น", vectorizer, best_model)
    predict_message("สวัสดีครับคุณแม่ พรุ่งนี้เลิกงานแล้วจะแวะไปกินข้าวเย็นด้วยนะ", vectorizer, best_model)
