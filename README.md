# AegisRange
AegisRange: Lightweight Attack Detection & Investigation Cyber Range

 Member 1 – Architecture + Red Team Lead

Hello everyone. our project is called AegisRange: Lightweight Attack Detection and Investigation Cyber Range.

AegisRange is a self-hosted cybersecurity training platform designed to demonstrate how cyberattacks can be simulated in a controlled environment, how the resulting evidence can be collected, and how suspicious activities can be detected and investigated.

The main goal of this project is to connect two important areas of cybersecurity: Red Team operations, which simulate attacks, and Blue Team operations, which detect and investigate those attacks.

I am Member 1, responsible for the overall architecture and Red Team leadership, including the lab environment, attack-scenario planning, and integration of the different components.

 System Architecture

First, let me explain the architecture.

Our project is designed around three virtual machines connected through an isolated VirtualBox Host-Only Network.

The first machine is Kali Linux, which acts as our attacker machine. It is used to simulate controlled cybersecurity attacks.

The second machine is Ubuntu Linux Server, which acts as our first target. It is used for the SSH authentication scenario.

The third machine is Windows 10, which acts as our second target. It is used to demonstrate suspicious file execution and endpoint activity.

The network uses the private subnet 10.10.10.0/24.

Kali uses the IP address 10.10.10.10, Ubuntu uses 10.10.10.20, and Windows uses 10.10.10.30.

The main reason for using an isolated network is safety. It allows us to perform controlled security testing without exposing the simulated attacks to external systems.

We use Vagrant and VirtualBox configurations to define and provision the virtual machines.

Red Team Attack Scenarios

As the Red Team Lead, my responsibility includes coordinating the attack scenarios and ensuring that they generate evidence that the detection team can investigate.

We designed two main scenarios.

The first scenario is an SSH brute-force simulation against the Linux server.

In this scenario, the Kali machine generates repeated failed authentication attempts against the Ubuntu server.

These attempts create authentication records in the Linux authentication logs, particularly in the SSH service logs.

This evidence can help the detection team identify repeated login failures from the same source address.

The second scenario is controlled malicious-file execution on the Windows target.

This scenario demonstrates how a suspicious file execution can generate endpoint evidence.

We focus on events such as process creation, file creation, and network activity.

Windows Sysmon is included in our architecture to provide additional endpoint visibility.

Both scenarios are designed to generate evidence that can be used by the detection and investigation components.


The next component is Aegis-Local.

Aegis-Local is the central detection and correlation component of our project.

Its purpose is to receive security logs from the target machines, store the records, and identify suspicious activity.

The documented backend design uses Python and FastAPI, while SQLite is used for data storage.

The current backend design includes a log-ingestion endpoint and an incident-correlation function.

For example, the implemented correlation logic raises an incident when at least three logs from the same source IP are received within five minutes.

The severity increases according to the number of matching logs.

The planned dashboard uses Streamlit to display incidents and support investigation.

This is important because detecting suspicious activity is not enough. A security analyst also needs to understand what happened and which evidence triggered the incident.


As Member 1, my main responsibility is the system architecture and Red Team coordination.

My contribution focuses on defining how the three virtual machines communicate, designing the isolated network structure, coordinating the attack scenarios, and connecting the Red Team activities with the detection team's requirements.

I also work on the overall integration plan so that the attack scenarios produce useful evidence for the detection and investigation workflow.

I coordinate with the other team members because the project depends on different components working together.

For example, the Red Team generates the activity, the detection team works with the resulting evidence, the backend handles ingestion and correlation, and the frontend presents the investigation results.



To conclude, AegisRange demonstrates an important cybersecurity workflow:

Attack, evidence generation, detection, correlation, and investigation.

The project provides a foundation for learning how security incidents can be detected and analyzed in a controlled laboratory environment.

Our future improvements include severity scoring, MITRE ATT&CK technique mapping, and virtual-machine snapshot restoration.

here is ny induvidual video link

https://youtu.be/C4JdNF6SzqU?si=JQEPAomaKrE67jx2
