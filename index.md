# CS373 Summer Write-Up Blog

This blog is being done as an ongoing weekly homework assignment for OSU's online CS373 course. It will follow my learning as the course progresses and, hopefully, show my growth through the term.
<div>
  
## Week 1 Write-Up: The Basics of Malware
This first week of class was choked full of information and as such was the typical first week experience for pretty much any class. We learned a whole lot of new terminology that was foriegn to many of us, we were introduced to an online Virtual Machine (VM) extravaganza, and were introduced to many new tools and techniques that I had personally never heard of. We also learned about what malware actually is, and why it exists and is created.

### What is Malware?
Malware is MALicious softWARE and comes in several different types. Some of these types are as follows:
* viruses: Code that is damaging to the system
  * Parasitic viruses: dependent on other files
  * Polymorphic viruses: has constantly changing code
* trojans: malware that pretends to be something else to infect your system
* Pontentially Unwanted Programs (PUPs): Things like adware, or a tower of toolbars for your browser of choice

### Why is Malware Created?
Malware can be created for many different reasons. Some people enjoy seeing the world burn and thus write Malware to do it. Others may do it for some sort of gain be it political or financial. Otheres still may do it for espionage. All the reasons are equally as threatening.

### The Classifications for the Job!
This week brought forth a slew of new vocabulary to in terms of categorizing files:
* White files: Files that are perfectly safe or allowed.
* Black files: Files that are not safe and should not be allowed.
* Gray files: Files that might be safe but we can't really tell.
* Sample: Any piece of malware.
* Goat: Something that gets sacrafice to a piece of malware.
* Replications: A recreation of a piece of malware.
* Hash: a value calculated based on the contents of a file.

### The Tools for the Job!
This week gave us a homework assignment to analyze a piece of malware. To do this, we were given access to a VM with several tools and the malware already pre-installed. The tools that we used were were:
* Flypaper: a program that stopped TCP/IP requests and also, I believe, stopped processes from exiting. ![Flypaper](/images/Flypaper.PNG)
* Fakenet: a program that simulates network traffic, sort of.![FakeNet](/images/FakeNet.PNG)
* Process Monitor: a program that allows you to look at every action every process is currently doing. ![ProcMonitor](/images/ProcMonitor.PNG)
* Process Explorer: a program that lets you look at the details behind every running process.![ProcExplorer](/images/ProcExplorer.PNG)
* Antispy: a program that also lets you look at the details behind every process but with differing information.![AntiSpy](/images/AntiSpy.PNG)
</div>
