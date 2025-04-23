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
    for label in os.listdir(path):
        target_names.append(label)
        with open(os.path.join(path, label, 'ALL_FILES.txt'), encoding="utf8") as f:
            lines = f.readlines()
            dataset_size[label] = len(lines)
            for payload in lines:
                if "\n" in payload:
                    X.append(payload.replace("\n", ""))
                    Y.append(INV_LABELS[label])
    return train_test_split(X, Y, test_size=test_size, random_state=random_state)



def get_dataset(path, test_size=0.25, random_state=42):
    X = []
    Y = []

    for label in names:
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

# Tokenize data
train_encodings = tokenizer(x_train, truncation=True, padding=True, max_length=500)
test_encodings = tokenizer(x_test, truncation=True, padding=True, max_length=500)

#import pickle
#with open('objs.pkl', 'wb') as f:  # Python 3: open(..., 'wb')
#    pickle.dump([train_encodings, test_encodings], f)
#
## Getting back the objects:
#with open('objs.pkl') as f:  # Python 3: open(..., 'rb')
#    train_encodings, test_encodings = pickle.load(f)


# Convert labels to PyTorch tensors
train_labels = torch.tensor(y_train).to(dml)
test_labels = torch.tensor(y_test).to(dml)


train_dataset = TextDataset(train_encodings, train_labels)
test_dataset = TextDataset(test_encodings, test_labels)

# Load the pre-trained model for sequence classification
model = DistilBertForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=len(target_names)).to(dml)

# Define training parameters
batch_size = 4
learning_rate = 5e-5
epochs = 1

# Create DataLoaders
train_dataloader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
eval_dataloader = DataLoader(test_dataset, batch_size=batch_size)

# Define optimizer
optimizer = AdamW(model.parameters(), lr=learning_rate)

# Define loss function (already included in the model)

# Training loop
print("Training...")
model.train()
for epoch in range(epochs):
    total_loss = 0
    for batch in tqdm(train_dataloader, desc=f"Epoch {epoch+1}"):
        optimizer.zero_grad()
        input_ids = batch['input_ids'].to(dml)
        attention_mask = batch['attention_mask'].to(dml)
        labels = batch['labels'].to(dml)
        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
        loss = outputs.loss
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    avg_train_loss = total_loss / len(train_dataloader)
    print(f"Epoch {epoch+1} Training Loss: {avg_train_loss:.4f}")


# model.save_pretrained ?? - from_pretrained(path) ??
torch.save(model.state_dict(), save_model_dir)

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

print("Finished running model: ", MODEL_NAME)