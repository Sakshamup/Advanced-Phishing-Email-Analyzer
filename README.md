# 🛡️ Advanced Phishing Email Analyzer
## 📌 Project Description
The Advanced Phishing Email Analyzer is a Streamlit-based web application that detects phishing emails using Machine Learning (ML) and Natural Language Processing (NLP) techniques. It analyzes email content, extracts URLs, and evaluates suspicious characteristics using a Random Forest Classifier for accurate phishing detection.

### 🚀 Features
- ✅ Phishing Detection: Analyzes email content and predicts if it is a phishing attempt or legitimate.
- 🔍 Detailed Analysis:
   - URL extraction and security evaluation.
   - Attachment and content behavior indicators.
- 📊 Dashboard and Reports:
   - Displays recent phishing trends.
   - Saves and shows previous analyses.
-🔒 Threat Intelligence: Provides insights into emerging phishing patterns.


### 🛠️ Tech Stack
- Frontend: Streamlit for interactive UI.
- Backend: Python with ML-based phishing detection model.
- ML Libraries:
   - sklearn for Random Forest Classifier.
   - TfidfVectorizer for text processing.
- Data Visualization: Plotly for interactive charts.

### 📂 Installation and Setup
1) Clone the repository:
```
git clone <repository_url>
cd phishing-analyzer
```
2) Install dependencies:
```
pip install -r requirements.txt
```
3) Run the application:
```
streamlit run app.py
```
### 📊 Usage
- Paste the email content (including headers, if possible) into the text area.
- Click on "Analyze Email".
- The app will:
   - Detect phishing with a confidence score.
   - Display URL analysis, content indicators, and potential risks.
- View phishing trends in the Threat Dashboard.
- Save and review your previous analyses.

### 🧠 Machine Learning Model
The project uses a Random Forest Classifier trained on:
- Text features: TF-IDF vectorized email content.
- Behavioral indicators: URL count, attachment presence, and suspicious words.
- URL features: Domain, IP usage, HTTPS presence, and path length.

### 📊 Visualization and Reporting
- The Threat Dashboard provides real-time phishing statistics and trends.
- Reports can be saved and revisited for historical reference.

### 🛡️ Security Tips
- Be cautious with suspicious URLs.
- Avoid clicking on shortened or unknown links.
- Always verify sender identities.
- Do not download attachments from unknown emails.
