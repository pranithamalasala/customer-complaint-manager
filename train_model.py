import pandas as pd
import pickle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# 1. Load the dataset we just created
data = pd.read_csv("complaints_dataset.csv")

# 2. Separate the Input (Text) and Output (Category & Priority)
X = data['description']
y_category = data['category']
y_priority = data['priority']

# 3. Create the "Brains" (Pipelines)
# We use CountVectorizer to turn words into numbers, and Naive Bayes to classify.

# Brain 1: Predicts Category
model_category = make_pipeline(CountVectorizer(), MultinomialNB())
model_category.fit(X, y_category)

# Brain 2: Predicts Priority
model_priority = make_pipeline(CountVectorizer(), MultinomialNB())
model_priority.fit(X, y_priority)

# 4. Save the Brains to a file
with open("model.pkl", "wb") as f:
    pickle.dump({'category_model': model_category, 'priority_model': model_priority}, f)

print("✅ SUCCESS: AI Model trained and saved as 'model.pkl'!")

# --- TEST IT HERE ---
test_text = ["The wifi is very slow and lagging"]
pred_cat = model_category.predict(test_text)[0]
pred_prio = model_priority.predict(test_text)[0]

print(f"\n🧪 TEST:")
print(f"Input: '{test_text[0]}'")
print(f"Predicted Category: {pred_cat}")
print(f"Predicted Priority: {pred_prio}")