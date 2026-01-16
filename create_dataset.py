import pandas as pd
import random

# Define the categories and their typical keywords
data_templates = {
    "Hardware": [
        "The {device} is broken and not turning on.",
        "Smoke is coming from the {device} unit.",
        "The {device} screen is flickering and blue.",
        "Mouse is not working.",
        "Keyboard keys are stuck.",
        "Printer is jamming paper continuously.",
        "The server fan is making a loud noise."
    ],
    "Software": [
        "I cannot install the {software} update.",
        "The {software} keeps crashing when I open it.",
        "Microsoft Office is showing an error code.",
        "The operating system is very slow.",
        "I need a license key for {software}.",
        "Adobe Reader is not responding."
    ],
    "Network": [
        "The Wifi is not connecting in the meeting room.",
        "Internet speed is very slow today.",
        "I cannot access the company portal page.",
        "VPN connection keeps dropping.",
        "LAN cable seems to be broken."
    ],
    "Account": [
        "I forgot my password and need a reset.",
        "My account is locked out.",
        "I cannot login to my email.",
        "Need access to the shared drive folder.",
        "Two-factor authentication is failing."
    ]
}

devices = ["laptop", "monitor", "CPU", "projector", "scanner", "server"]
softwares = ["Excel", "Python", "Zoom", "Teams", "Photoshop", "Outlook"]

# Generate random data
dataset = []

for _ in range(200):  # Generate 200 Hardware examples
    text = random.choice(data_templates["Hardware"]).replace("{device}", random.choice(devices))
    priority = "High" if "Smoke" in text or "server" in text else "Medium"
    if "Mouse" in text or "Keyboard" in text: priority = "Low"
    dataset.append([text, "Hardware", priority])

for _ in range(150):  # Generate 150 Software examples
    text = random.choice(data_templates["Software"]).replace("{software}", random.choice(softwares))
    priority = "High" if "crashing" in text else "Medium"
    dataset.append([text, "Software", priority])

for _ in range(150):  # Generate 150 Network examples
    text = random.choice(data_templates["Network"])
    priority = "High" if "VPN" in text or "portal" in text else "Medium"
    dataset.append([text, "Network", priority])

for _ in range(100):  # Generate 100 Account examples
    text = random.choice(data_templates["Account"])
    priority = "High" if "locked" in text else "Low"
    dataset.append([text, "Account", priority])

# Save to CSV
df = pd.DataFrame(dataset, columns=["description", "category", "priority"])
df.to_csv("complaints_dataset.csv", index=False)

print("✅ SUCCESS: 'complaints_dataset.csv' created with", len(df), "examples!")