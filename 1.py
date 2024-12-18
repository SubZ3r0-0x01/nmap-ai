import pandas as pd
import os
import joblib
import re
import nmap
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.utils import resample
from termcolor import colored

# Load the dataset with better handling of encoding issues
def load_dataset(file_path):
    try:
        dataset = pd.read_csv(file_path, encoding='utf-8')
    except UnicodeDecodeError:
        dataset = pd.read_csv(file_path, encoding='latin1')
    return dataset

def preprocess_data(dataset):
    # Fill missing values in 'Ports Related To' with 'No Ports'
    dataset['Ports Related To'] = dataset['Ports Related To'].fillna('No Ports').astype(str)

    # Text cleanup: Lowercase, remove special characters, etc.
    dataset['One Line Description'] = dataset['One Line Description'].apply(
        lambda x: re.sub(r'[^a-zA-Z0-9 ]', '', str(x).lower())
    )

    # Feature: Number of ports
    dataset['Num Ports'] = dataset['Ports Related To'].apply(
        lambda x: len(re.findall(r'\d+', x)) if x != 'No Ports' else 0
    )

    # Group ports into categories (well-known, registered, dynamic)
    def categorize_ports(ports):
        port_numbers = [int(port) for port in re.findall(r'\d+', ports)]
        categories = []
        for port in port_numbers:
            if port <= 1023:
                categories.append('well-known')
            elif 1024 <= port <= 49151:
                categories.append('registered')
            else:
                categories.append('dynamic')
        return ','.join(categories) if categories else 'none'

    dataset['Port Categories'] = dataset['Ports Related To'].apply(categorize_ports)

    return dataset

# Handle class imbalance by upsampling
def balance_classes(dataset):
    categories = dataset['Category'].value_counts()
    majority_class = categories.idxmax()
    balanced_dataset = dataset[dataset['Category'] == majority_class]

    for category in categories.index:
        if category != majority_class:
            minority_class = dataset[dataset['Category'] == category]
            minority_upsampled = resample(
                minority_class, 
                replace=True, 
                n_samples=len(dataset[dataset['Category'] == majority_class]), 
                random_state=42
            )
            balanced_dataset = pd.concat([balanced_dataset, minority_upsampled])
    return balanced_dataset

# Scanning workflow (Nmap integration)
def scanning_workflow(dataset, ip="45.33.32.156"):
    nm = nmap.PortScanner()
    
    # Create a file to save the results
    result_file = "scan_results.txt"
    with open(result_file, 'w') as file:
        file.write(f"Scanning Report for IP: {ip}\n")
        file.write("=" * 50 + "\n\n")

    # Perform Nmap scan for all categories
    categories = dataset['Category'].unique()

    for category in categories:
        print(colored(f"Scanning for category: {category}...", 'green'))

        # Get the scripts associated with the selected category
        filtered_data = dataset[dataset['Category'] == category]
        scripts = filtered_data['Script Name'].tolist()

        # Remove duplicates from the script list
        unique_scripts = list(set(scripts))
        script_str = ",".join(unique_scripts)  # Combine all unique script names into a single string
        
        # Run the actual Nmap scan with -Pn (pingless scan) and the selected scripts
        command = f"nmap -Pn -p- --script={script_str} {ip}"
        print(colored(f"Executing Nmap command for category {category}: {command}", 'yellow'))
        
        # Scan the IP for the category
        nm.scan(ip, '1-1024', arguments=f'--script={script_str}')

        # Collect the results
        open_ports = [port for port, state in nm[ip]['tcp'].items() if state['state'] == 'open']
        
        # Save the results to the file
        with open(result_file, 'a') as file:
            file.write(f"Category: {category}\n")
            file.write(f"Scripts Used: {script_str}\n")
            file.write(f"Open Ports: {open_ports}\n")
            file.write("-" * 50 + "\n")

    print(colored(f"Scan completed. Results saved to {result_file}.", 'green'))

# Check accuracy only once and save to a file
def check_accuracy_once(best_model, tfidf_vectorizer, dataset):
    accuracy_file = "accuracy_results.txt"

    if os.path.exists(accuracy_file):
        with open(accuracy_file, 'r') as file:
            accuracy = file.read().strip()
        print(colored(f"Using previously saved accuracy: {accuracy}", 'blue'))
        return

    # Preprocess and prepare the data
    print(colored("Checking accuracy once...", 'magenta'))
    X_text = dataset['One Line Description']
    X_ports = dataset[['Num Ports', 'Port Categories']]
    y = dataset['Category']

    # Convert text to TF-IDF features
    X_text_tfidf = tfidf_vectorizer.transform(X_text)
    
    X_ports_dummies = pd.get_dummies(X_ports['Port Categories']).reset_index(drop=True)
    X_ports_num = X_ports[['Num Ports']].reset_index(drop=True)

    X = pd.concat([pd.DataFrame(X_text_tfidf.toarray(), columns=tfidf_vectorizer.get_feature_names_out()), X_ports_dummies, X_ports_num], axis=1)

    # Evaluate accuracy
    y_pred = best_model.predict(X)
    accuracy = accuracy_score(y, y_pred) * 100
    print(colored(f"Accuracy: {accuracy:.2f}%", 'green'))

    with open(accuracy_file, 'w') as file:
        file.write(f"{accuracy:.2f}%")

# Main script logic
def main():
    print(colored("Starting the main script...", 'yellow'))

    # Load and preprocess dataset
    print(colored("Loading dataset from: nmap_scripts.csv", 'blue'))
    dataset = load_dataset("nmap_scripts.csv")
    print(colored("Dataset loaded successfully.", 'green'))

    print(colored("Preprocessing data...", 'blue'))
    dataset = preprocess_data(dataset)
    print(colored("Data preprocessing completed.", 'green'))

    # Handle class imbalance by upsampling
    print(colored("Balancing class distribution...", 'blue'))
    dataset = balance_classes(dataset)
    print(colored("Class balancing completed.", 'green'))

    # Check accuracy only once
    if os.path.exists("nmap_model.pkl") and os.path.exists("tfidf_vectorizer.pkl"):
        print(colored("Loading previously saved model and vectorizer.", 'blue'))
        best_model = joblib.load("nmap_model.pkl")
        tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")
    else:
        print(colored("Training the model...", 'blue'))

        # Prepare data for training
        X_text = dataset['One Line Description']
        X_ports = dataset[['Num Ports', 'Port Categories']]
        y = dataset['Category']

        tfidf_vectorizer = TfidfVectorizer(max_features=500)
        X_text_tfidf = tfidf_vectorizer.fit_transform(X_text)

        # Combine text and numerical features into a single dataset
        X_text_tfidf_df = pd.DataFrame(X_text_tfidf.toarray(), columns=tfidf_vectorizer.get_feature_names_out()).reset_index(drop=True)
        X_ports_dummies = pd.get_dummies(X_ports['Port Categories']).reset_index(drop=True)
        X_ports_num = X_ports[['Num Ports']].reset_index(drop=True)

        X = pd.concat([X_text_tfidf_df, X_ports_dummies, X_ports_num], axis=1)

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train a Random Forest classifier with hyperparameter tuning
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10]
        }

        rf = RandomForestClassifier(random_state=42)
        grid_search = GridSearchCV(rf, param_grid, cv=5, n_jobs=-1)
        grid_search.fit(X_train, y_train)

        best_model = grid_search.best_estimator_

        # Save the model and vectorizer
        print(colored("Saving the model and vectorizer...", 'blue'))
        joblib.dump(best_model, "nmap_model.pkl")
        joblib.dump(tfidf_vectorizer, "tfidf_vectorizer.pkl")

    # Check accuracy (only once)
    check_accuracy_once(best_model, tfidf_vectorizer, dataset)

    # Check if the scan results file exists
    if os.path.exists("scan_results.txt"):
        print(colored("Scan report already exists.", 'yellow'))

        # Prompt user to provide a single IP or IP list
        ip_input = input("Enter a single IP address or provide a path to a text file with a list of IPs: ").strip()

        # If a file is provided
        if os.path.exists(ip_input) and ip_input.endswith('.txt'):
            with open(ip_input, 'r') as file:
                ip_list = [line.strip() for line in file.readlines()]
            for ip in ip_list:
                scanning_workflow(dataset, ip)
        else:
            # If a single IP is provided
            scanning_workflow(dataset, ip_input)
    else:
        # If scan results do not exist, perform a scan on the demo IP
        scanning_workflow(dataset, "45.33.32.156")

if __name__ == "__main__":
    main()
