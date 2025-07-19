import json
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from config import *

def load_data(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def compute_metrics(data, cwe_ids):
    results = {}

    for cwe in cwe_ids:
        y_true = []
        y_pred = []

        for item in data:
            true_cwe = item.get("cwe")
            pred_cwe = item.get("predicted_cwe")

            y_true.append(1 if true_cwe == cwe else 0)
            y_pred.append(1 if pred_cwe == cwe else 0)

        TP = sum((t == 1 and p == 1) for t, p in zip(y_true, y_pred))
        TN = sum((t == 0 and p == 0) for t, p in zip(y_true, y_pred))
        FP = sum((t == 0 and p == 1) for t, p in zip(y_true, y_pred))
        FN = sum((t == 1 and p == 0) for t, p in zip(y_true, y_pred))

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        results[cwe] = {
            "TP": TP, "TN": TN, "FP": FP, "FN": FN,
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1": round(f1, 4)
        }

    y_true_ood = []
    y_pred_ood = []

    for item in data:
        true_cwe = item.get("cwe")
        pred_cwe = item.get("predicted_cwe")

        is_ood = true_cwe not in cwe_ids
        if is_ood:
            y_true_ood.append(1) 
            y_pred_ood.append(1 if pred_cwe == "NO" else 0) 

    if y_true_ood:
        acc = accuracy_score(y_true_ood, y_pred_ood)
        prec = precision_score(y_true_ood, y_pred_ood, zero_division=0)
        rec = recall_score(y_true_ood, y_pred_ood, zero_division=0)
        f1 = f1_score(y_true_ood, y_pred_ood, zero_division=0)

        TP = sum((t == 1 and p == 1) for t, p in zip(y_true_ood, y_pred_ood))
        TN = sum((t == 0 and p == 0) for t, p in zip(y_true_ood, y_pred_ood))
        FP = sum((t == 0 and p == 1) for t, p in zip(y_true_ood, y_pred_ood))
        FN = sum((t == 1 and p == 0) for t, p in zip(y_true_ood, y_pred_ood))

        results["OOD"] = {
            "TP": TP, "TN": TN, "FP": FP, "FN": FN,
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1": round(f1, 4)
        }

    return results

def print_metrics(metrics):
    print(f"{'CWE':<10} {'TP':<5} {'TN':<5} {'FP':<5} {'FN':<5} {'Acc':<8} {'Prec':<8} {'Recall':<8} {'F1':<8}")
    for cwe, values in metrics.items():
        print(f"{cwe:<10} {values['TP']:<5} {values['TN']:<5} {values['FP']:<5} {values['FN']:<5} "
              f"{values['Accuracy']:<8} {values['Precision']:<8} {values['Recall']:<8} {values['F1']:<8}")

if __name__ == "__main__":
    json_path = "output/query30_results.json"
    data = load_data(json_path)
    metrics = compute_metrics(data, CWE_ID)
    print_metrics(metrics)