# --- 0. Install dependencies ---
!pip install transformers datasets scikit-learn

# --- 1. Import libraries ---
import json
import torch
from torch.utils.data import Dataset
from transformers import RobertaTokenizer, RobertaForSequenceClassification, Trainer, TrainingArguments
from sklearn.model_selection import train_test_split
from google.colab import files

# --- 2. Upload your dataset ---
print("Please upload your JSONL dataset (security_dataset_all_langs.jsonl)")
uploaded = files.upload()
dataset_path = list(uploaded.keys())[0]

# --- 3. Load .jsonl dataset ---
data = []
with open(dataset_path, "r") as f:
    for line in f:
        data.append(json.loads(line.strip()))

# --- 4. Preprocess dataset ---
error_labels = sorted(set(d['error_name'] for d in data))
label2id = {label: i for i, label in enumerate(error_labels)}
id2label = {i: label for label, i in label2id.items()}

class CodeVulnDataset(Dataset):
    def __init__(self, data, tokenizer, max_len=256):
        self.data = data
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        item = self.data[idx]
        code = item['code']
        label = label2id[item['error_name']]
        enc = self.tokenizer(
            code, truncation=True, padding='max_length', max_length=self.max_len, return_tensors='pt'
        )
        return {
            'input_ids': enc['input_ids'].squeeze(0),
            'attention_mask': enc['attention_mask'].squeeze(0),
            'labels': torch.tensor(label, dtype=torch.long)
        }

# --- 5. Initialize tokenizer + model ---
tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaForSequenceClassification.from_pretrained(
    "microsoft/codebert-base",
    num_labels=len(error_labels),
    id2label=id2label,
    label2id=label2id
)

# --- 6. Detect device ---
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)
model.to(device)

# --- 7. Split dataset ---
train_data, test_data = train_test_split(data, test_size=0.1, random_state=42)
train_dataset = CodeVulnDataset(train_data, tokenizer)
test_dataset = CodeVulnDataset(test_data, tokenizer)

# --- 8. Training arguments ---
training_args = TrainingArguments(
    output_dir="./codebert_vuln",

    learning_rate=1e-4,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    num_train_epochs=1,
    weight_decay=0.01,
    save_total_limit=2,
    logging_steps=500,
    report_to="none",
    fp16=False
)

# --- 9. Trainer ---
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset
)

# --- 10. Train model ---
trainer.train()

# --- 11. Save model safely ---
trainer.save_model("./codebert_vuln_safe")

# --- 12. Inference function ---
def classify_code(snippet):
    model.eval()
    enc = tokenizer(snippet, truncation=True, padding='max_length', max_length=256, return_tensors='pt')
    enc = {k: v.to(device) for k, v in enc.items()}
    with torch.no_grad():
        logits = model(**enc).logits
        pred_id = logits.argmax(-1).item()
    return id2label[pred_id]

# --- 13. Example inference ---
example_snippets = [
    'lst = [0]*10\nlst[15] = 1',  # Buffer overflow Python
    'cursor.execute("SELECT ..."+user_input)',  # SQL Injection Python
    'password="1234"'  # Hardcoded credentials Python
]

for snippet in example_snippets:
    print(f"Code:\n{snippet}\nPredicted Vulnerability: {classify_code(snippet)}\n")
