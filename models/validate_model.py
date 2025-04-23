import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import numpy as np
import os
from torch.utils.data import DataLoader
from torch.optim import AdamW
from tqdm import tqdm
from torch_dataset import TextDataset

def relative_path(path: str) -> str:
    script_dir = os.path.dirname(__file__)
    return os.path.join(script_dir, path)


try:
    import torch_directml

    ## Check if DirectML is available and set the device
    if torch_directml.is_available():
        dml = torch_directml.device()
        print(f"Using DirectML device: {dml}")
    else:
        print("DirectML is not available. Training will happen on CPU.")
        dml = torch.device("cpu")
except:
    dml = torch.device("cpu")


dataset_size = {}
target_names = []
# "data/datasets"
dataset_path = relative_path("../data/fwaf-dataset/training")
save_model_dir = relative_path("../results/model-fwaf-dataset.pth")

#LABELS = {}
#INV_LABELS = {}
#for i, label in enumerate(os.listdir(dataset_path)):
#    LABELS[i] = label
#    INV_LABELS[label] = i


names = ["goodqueries", "badqueries"]
target_names = ["goodqueries", "badqueries"]

LABELS = { k:v for (k,v) in zip(range(len(target_names)), target_names)}
INV_LABELS = { k:v for (k,v) in zip(target_names, range(len(target_names)))}
def get_dataset(path, test_size=0.25, random_state=42):
    X = []
    Y = []

    for label in names:
        #with open(os.path.join(path, label, 'ALL_FILES.txt'), encoding="utf8") as f:
        with open(os.path.join(path, label+".txt"), encoding="utf8") as f:
            lines = f.readlines()
            dataset_size[label] = len(lines)
            for payload in lines:
                if "\n" in payload:
                    X.append(payload.replace("\n", ""))
                    Y.append(INV_LABELS[label])
    return train_test_split(X, Y, test_size=test_size, random_state=random_state)


x_train, x_test, y_train, y_test = get_dataset(dataset_path)




MODEL_NAME = 'distilbert-base-uncased'
print("Running model: ".upper(), MODEL_NAME.upper())
print("\n\n\n")

tokenizer = DistilBertTokenizer.from_pretrained(MODEL_NAME)

test_labels = torch.tensor(y_test).to(dml)
test_encodings = tokenizer(x_test, truncation=True, padding=True, max_length=500)

test_dataset = TextDataset(test_encodings, test_labels)

# Load the pre-trained model for sequence classification
model = DistilBertForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=len(target_names)).to(dml)
model.load_state_dict(torch.load(save_model_dir, weights_only=True))
model.eval()

#print("saving from hugging")
#model.save_pretrained(relative_path("../resuts/pretrained-fwaf.pt"), from_pt=True)
#model = DistilBertForSequenceClassification.from_pretrained(relative_path("../resuts/pretrained-fwaf.pt"))

batch_size = 4
eval_dataloader = DataLoader(test_dataset, batch_size=batch_size)

# Evaluation loop
print("\nValidating...")
model.eval()
total_eval_loss = 0
all_predictions = []
all_labels = []
with torch.no_grad():
    for batch in tqdm(eval_dataloader, desc="Evaluating"):
        input_ids = batch['input_ids'].to(dml)
        attention_mask = batch['attention_mask'].to(dml)
        labels = batch['labels'].to(dml)
        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
        loss = outputs.loss
        total_eval_loss += loss.item()
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)
        all_predictions.extend(predictions.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

avg_eval_loss = total_eval_loss / len(eval_dataloader)
accuracy = accuracy_score(all_labels, all_predictions)
precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_predictions, average='weighted')

evaluation_results = {
    'eval_loss': avg_eval_loss,
    'eval_accuracy': accuracy,
    'eval_precision': precision,
    'eval_recall': recall,
    'eval_f1': f1
}

print("Evaluation Results:")
print(evaluation_results)
