# CS373 Summer Write-Up Blog
 
This blog is being done as an ongoing weekly homework assignment for OSU's online CS373 course. It will follow my learning as the course progresses and, hopefully, show my growth throughout the term.

## Week 2 Write-Up: Advanced Forensic Methods and Tools
This second week, like last week, was also full of fresh new information that I had never heard about. For the most part, the tools we were introduced to were just as foregin as the ones from last week. To put this week's lessons simply, we learned about properly reacting to incidents using the correct forensics methods. Similar to last week, the new tools we were introduced to was used to practice the forensics methods.

### What is an Incident?
An incident is something that, if I understood correctly prompts a forensic investigation. These incidents come in several different types as follows:
* Fraud
* Intellectual Property Theft
* Hack Intrusions
* Data Breaches
* Inappropriate use of an internet connection
* Child Exploitation
* eDiscovery

### What is Forensic Computing?
Forensic Computing is the thorough gathering of digital data in order to identify information about a given incident. Forensics computing tends to follow the three step pattern of:
* Evidence Acquisition
* Investigation and analysis
* Reporting results

Forensic computing can be roughly categorized into three overarching classes:
* Live forensics
* Post-mortem based forensics
* Network based forensics
The identification, preservation, analysis, and presentation of evidence is the driving force of forensic computing

### What Exactly is Evidence?
Evidence is information that is used to determine whether or not a narrative is true. When evidence is to be used within the court of law, the evidence must be admissible. This means that the evidence is accepted by the court.

### How Should Evidence be Handled?
The short answer: very carefully. Precautions must be put in place in order to safeguard the wholeness of evidence. There are several steps that must be carried out in order to ensure the evidence's completeness such as:
* Creating an MD5 or SHA1 hash of the entire disk and its partitions.
* Creating copies of the evidence to analyze instead of the main source.
* Creating an MD5 or SHA1 hash of the copies and ensuring that they match the main source's hash.
* Physically secure the original source somewhere safe.

### What is the Incident Response Process?
The incident response process is a seven step process by which action should be taken if or when an  incident is detected. The seven steps are as follows:
* Incident response team preparation: The team must be prepared for a incident at any time.
* Incident detection: The actual detection of the incident.
* Initial response: The team's immediate response to the incident.
* Formulate response strategy: The team creates a strategy to tackle or otherwise handle the incident.
* Data collection: Data regarding the incident gets collected.
* Forensic Analysis: The data collected during the data collection stage gets analyzed.
* Document findings: Document everything from beginning to end that happened regarding the incident.

### Where Do We Look For Evidence?
When we are looking for evidence, what we want to acquire depends on the scenario. There are three main categories of information to acquire:
* If we want to find information in memory, we would want to make sure we took everything responsible for virtual and physical memory e.g. RAM sticks.
* If we want to find information on the drive, we would want to make sure we had either the entire physical drive or the partitions where all the information is.
* If we want to find information within network traffic, we would want to make sure that we were enacting full packet capturing.

### The One Thing You Shouldn't Do During Initial Response!
As long as it is safe to do so, you should refrain from simply pulling the plug on (or turning off) a machine. This loss of powers will more than likely destroy evidence. Since critical data may be stored in some volatile way, all care must go saving as much evidence as possible.

### The Tools For Information Gathering!
In order to collect data, we were given access to several new applications that we get to try out. The applications include:
* FTK Imager: A tool that helps with evidence acquisition. ![FTKImager](/images/FTKImager.PNG)
* Volatility: A memory forensics framework with a whole host of useful commands. ![Volatility](/images/Volatility.PNG)
* Yara: Malware plugins for Volatility. I'll add an image of the editor even though I have no idea what it does. ![YaraEditor](/images/YaraEditor.PNG)

### Anything Else?
I'm still working through several of the follow along, it's been a busy week. I'll hopefully have better information to add next week!

### Citations
Much of the information on this blog post is provided by the Basics of Malware 1 & 2 slides created by Christiaan Beek.

----------------------------------------------------------------------------------------------------------------------------------------

## Week 1 Write-Up: The Basics of Malware
This first week of class was choked full of information and as such was the typical first week experience for pretty much any class. We learned a whole lot of new terminology that was foriegn to many of us, we were introduced to an online Virtual Machine (VM) extravaganza, and were introduced to many new tools and techniques that I had personally never heard of. We also learned about what malware actually is, and why it exists and is created.
 
### What is Malware?
Malware is MALicious softWARE and comes in several different types. Some of these types are as follows:
* viruses: Code that is damaging to the system
  * Parasitic viruses: dependent on other files
  * Polymorphic viruses: has constantly changing code
* trojans: malware that pretends to be something else to infect your system
* Potentially Unwanted Programs (PUPs): Things like adware, or a tower of toolbars for your browser of choice
 
### Why is Malware Created?
Malware can be created for many different reasons. Some people enjoy seeing the world burn and thus write Malware to do it. Others may do it for some sort of gain be it political or financial. Others still may do it for espionage. All the reasons are equally as threatening.
 
### The Classifications for the Job!
This week brought forth a slew of new vocabulary to in terms of categorizing files:
* White files: Files that are perfectly safe or allowed.
* Black files: Files that are not safe and should not be allowed.
* Gray files: Files that might be safe but we can't really tell.
* Sample: Any piece of malware.
* Goat: Something that gets sacrificed to a piece of malware.
* Replications: A recreation of a piece of malware.
* Hash: a value calculated based on the contents of a file.
 
### The Tools for the Job!
To properly analyze malware, we were given access to a VM with several tools pre-installed. The tools that we learned about and used this week were:
* Flypaper: a program that stopped TCP/IP requests and also, I believe, stopped processes from exiting. ![Flypaper](/images/Flypaper.PNG)
* Fakenet: a program that simulates network traffic, sort of.![FakeNet](/images/FakeNet.PNG)
* Process Monitor: a program that allows you to look at every action every process is currently doing. ![ProcMonitor](/images/ProcMonitor.PNG)
* Process Explorer: a program that lets you look at the details behind every running process.![ProcExplorer](/images/ProcExplorer.PNG)
* Antispy: a program that also lets you look at the details behind every process but with differing information.![AntiSpy](/images/AntiSpy.PNG)
 
### The First Lab
This week gave us insight into how the rest of the course is going to go, at least in terms of homework. For this assignment we were given some malware that we were to dynamically analyze and report about our findings. We first started off by renaming the program to evil.exe, always a good start to any assignment. Then we ran all our fancy tool I mentioned earlier followed by running evil itself. I had a hard time actually figuring out the goal behind the sample as there was little to go off of. I did find out after doing my best with the tools that some of the files the sample creates might be giving access to our system to someone else.
 
### Citations
Much of the information on this blog post is provided by the Basics of Malware 1 & 2 slides created by Christiaan Beek.


