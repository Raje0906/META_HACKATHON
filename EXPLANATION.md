# 🧠 Understanding the SOC Simulator Project

Welcome! If cybersecurity or reinforcement learning (RL) is a new domain for you, this guide will break down the entire project in simple, easy-to-understand terms.

---

## 🛡️ 1. What is a "SOC"?

**SOC** stands for **Security Operations Center**. 
Imagine a real-world control room full of screens, where security analysts sit and monitor a company's computer networks 24/7. 

Their job is to look at **logs** (records of every action taken on the network, like who logged in and from where) and **alerts** (automated warnings that something looks suspicious).

If an analyst spots a hacker (called a "threat actor"), they must take **actions** to stop them, such as blocking the hacker's IP address or turning off the compromised server.

### The Problem:
There are billions of logs generated every day, but not enough human analysts to read them. This causes "alert fatigue," where humans miss real attacks because they are drowning in false alarms.

### Our Solution:
We built a **Simulator** for a SOC. The goal is to train an **AI Agent** to act exactly like a human SOC analyst.

---

## 🤖 2. How the AI Agent Works (Reinforcement Learning)

This project is built using the **OpenEnv** framework, which is designed for Reinforcement Learning (RL). Because we do not have a massive dataset of human SOC analysts to train on, we skip Supervised Fine-Tuning (SFT) and rely entirely on RL. We start with a smart base model (like `Llama-3-8B-Instruct`), give it a prompt explaining the log format, and then use RL to teach it how to act. In RL, you train an AI by putting it in an environment, letting it take actions, and giving it "rewards" (points) or "penalties" (negative points) based on whether it did a good job.

Think of it like training a dog:
1. **Observation:** The AI "looks" at the current state of the network (the logs, the alerts, the risk score).
2. **Action:** The AI decides what to do (e.g., "Block IP 185.220.101.47" or "Ignore").
3. **Reward:** The environment tells the AI how it did. 
   - Good action (blocking a hacker)? **+0.30 points**. 
   - Bad action (blocking Google)? **-0.15 points (False Positive penalty)**.
   - Doing nothing while under attack? **-0.20 points**.
4. **Step & Repeat:** The AI repeats this process step-by-step until the attack is stopped or it runs out of time.

---

## 🧩 3. The Big Pieces of Our Project

Here is how the code is organized to make this simulator work:

### 📡 The Communication Layer (`server/app.py` & `openenv.yaml`)
OpenEnv requires our simulator to run as a web server (FastAPI). The AI talks to our server using HTTP requests:
- `POST /reset`: The AI says, "Start a new attack scenario."
- `POST /step`: The AI says, "I want to take this action."
- `GET /score`: The AI says, "The scenario is over, what was my final grade?"

### 🗂️ The Data Structure (`models.py`)
To make sure the AI doesn't just guess randomly, we force it to communicate using structured formats (called **Pydantic models**).
- **`SOCObservation`**: The data we send *to* the AI (the dashboard).
- **`SOCAction`**: The strict format the AI must use to reply (it can only choose from 5 specific actions: `block_ip`, `flag_user`, `isolate_host`, `escalate_alert`, or `ignore`).

### 🎮 The World (`env/soc_environment.py`)
This is the "Game Engine." It keeps track of the current state, processes the AI's actions, calculates the rewards, and decides when the simulation is over.

---

## ⚔️ 4. The Three Attack Scenarios (Tasks)

We created three distinct "levels" for the AI to beat. Each task represents a real-world cyberattack.

### 🟢 Level 1: Easy (`tasks/easy_task.py`)
**The Attack:** A hacker sends a fake "Phishing" email to an employee named Alice. Alice clicks the link, and her password is stolen. The hacker immediately logs into the company network from Russia using Alice's stolen password.
**What the AI must do:** Notice the impossible travel (Alice was in the US, now she's in Russia 10 minutes later), block the Russian IP address, and flag Alice's account as compromised.

### 🟡 Level 2: Medium (`tasks/medium_task.py`)
**The Attack:** A hacker tries to guess the "finance.admin" password by trying 23 different incorrect passwords really fast (called a "Brute Force" attack). Finally, they guess it correctly and log in. Once inside, they start snooping around.
**What the AI must do:** Notice the rapid failed logins followed by a success. To make it tricky, we added "noise" (a random, innocent IP address). The AI must block only the bad IPs and isolate the hacked server, without getting tricked by the noise (which would cause a False Positive penalty).

### 🔴 Level 3: Hard (`tasks/hard_task.py`)
**The Attack:** This is an "APT" (Advanced Persistent Threat) attack, which means it happens in multiple stages over time:
1. **Reconnaissance:** The hacker scans the network to find a weak server.
2. **Initial Access:** They hack a web server.
3. **Lateral Movement:** They steal an internal password and jump from the web server to the highly restricted Database server.
4. **Exfiltration:** They steal 4.2 Gigabytes of sensitive company data and send it to their own server.
**What the AI must do:** The AI must track the hacker's movements step-by-step and use a combination of actions (Isolate the web server, Isolate the database, Block the hacker's master server, and Escalate to human experts because data was stolen).

---

## ⚖️ 5. The Graders (`graders/`)

At the end of each task, the "Grader" looks at every action the AI took and assigns a final score between **0.0 (Terrible)** and **1.0 (Perfect)**. This score is exactly what researchers will use to determine if a new LLM (like Llama 3 or GPT-4) is getting smarter at cybersecurity.

*Note on verification*: We intentionally chose strict **programmatic, rule-based verification** rather than using an "LLM-as-a-judge". While LLM judges can provide intermediate reasoning checks, they are extremely vulnerable to "reward hacking" (where the training model manipulates the judge). Our programmatic environment calculates ground-truth success definitively, making it much more robust for RL.

---

## 🚀 6. The Baseline (`inference.py`)

To prove our environment works, we included a script that tests an actual AI against it. It connects to an LLM (Language Model), shows the LLM the SOC dashboard, asks it what to do, and sends that action back to the environment. 

If you run `inference.py` without an API key, we even included a "Heuristic Agent"—a set of hardcoded rules (if X happens, do Y)—to ensure you can always test the environment without needing an OpenAI key.
