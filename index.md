# CS373 Summer Write-Up Blog
 
This blog is being done as an ongoing weekly homework assignment for OSU's online CS373 course. It will follow my learning as the course progresses and, hopefully, show my growth throughout the term.

## Week 4 Write-Up: Vulnerabilities and Exploits
Week four covered the manipulation of software and the usage of exploits on vulnerabilities on said software. After a little bit of a history lesson about the exploitation of software, we were introduced to a new tool and were given a little bit of practice on exploiting a simple program's vulnerabilities. We did not, however, learn anything about discovering vulnerabilities; we only learned about exploiting known vulnerabilities.

### What is Software Manipulation?
Software manipulation is the taking control of a piece of software. This is done in one of two ways: 
* The taking advantage of bugs that produce undefined behavior.
* The taking advantage of improper configurations such as bad passwords.

### What Get Targeted?
In the past, if someone wanted to attack an organization, they would attack the perimeter of that organization. This means that the attack vectors would be those that directly interact with the internet like the organization's website. Nowadays, organizations have significantly hardened the defenses on their perimeters. This means that an attacker today is more likely to attack the users inorder to gain access to the less hardened interior of the organization.

### What Tools Do We Use?
We were only introduced to one tool this week for the usage of software exploitation, and this tool is called WinDbg.
![WinDbg](/images/WinDbg.PNG)

With this tool, we are able to analyze what exactly a process is doing. Using this, we can force a bug to happen within a process and then try to figure out how we can manipulate it.

### The Exploit Lab
This week we were tasked with following along and working on a lab. This lab was divided into three lessons each with questions we had to answer.

#### Lesson 1 Questions
![Lesson1Questions](/images/Lesson1Questions.PNG)

Lesson 1 allowed us to practice the basics of using WinDbg on a (for testing purposes) website. We covered simple things like what memory address certain parts get loaded at, the values of registers at certain points, and the usage of commands such as `u`, `bp`, `du poi`, and `g`. We also got a fun part where the unicode in one of the registers read "FluffyBunniesDontFlapOrQuack."

#### Lesson 2 Questions
![Lesson2Questions](/images/Lesson2Questions.PNG)

Lesson 2 is where we gain enough understanding to exploit the vulnerabilities and then attacking. We first deconstruct the vulnerable function in question and determine the data type of its inputs. Then we determine what the vulnerable data is using three methods. We "smash the stack" and overflow. I'm assuming this is done with the letter "A" as registers that are affected are the sequence of 41414141. Then, we "stomp the stack" in that we manipulate memory that is being used in a manner that conflicts with what is currently using the memory. 
![StompTheStack](/images/StompTheStack.PNG)

Then we determine the address of the function that contains the vulnerability 

----------------------------------------------------------------------------------------------------------------------------------------

## Week 3 Write-Up: Malware Defense
This week covered how malware attacks and shared some methods and tools that help defend against these attacks. This week was fairly hands-on with the tools and we were provided with many labs to help give some understanding about the tools. After we learned enough theory, it was time to put in the practice. We were first tasked with creating Yara rules for several test files. Afterwards, we were asked to test out Cuckoo. Finally, we were asked to put it all together.

### How Does Malware Attack?
The majority of malware follows an attack pattern the boils down into the following steps:
* Execute code on a system
* Conceal one's self on a system
* Persist on a system
* Harvest data from a system
* Get the data back to the attacker

### How Do We Defend Against an Attack?
There are several popular technologies and methods that lead to a decent defense against malware. Most, if not all, techniques are essentially content engines that interpret content rules. What this means is that the techniques all have a set of guidelines they use to determine whether whatever they are looking at should be allowed through or not. 

### What is Yara?
Yara and Yara Editor are tools that allow the matching of patterns found between files using a rule-based approach. This means that you create a rule based on information found within the sample files, and then search for files that have the same sort of signatures. These signatures are usually in the form of strings expressed like "mystring," and byte patterns/hexadecimal strings expressed as {43 72 61 7A 79}. You can then use these signatures with conditional statements (basically boolean statements) to match to the correct files.
![YaraExampleRule](/images/YaraExampleRule.PNG)
In the above image, you can see that I have created a rule named "exampleRule." This rule contains variables for the strings "anexamplestring.exe" and "yaraiscool" with a conditional that ors the two of them. When search through files, this rule will search for either one of these strings and return a hit if they are found.

### Using Yara!
Now for the (sort of) real thing. We were tasked with creating several rules for samples in some provided folders. Each folder needed its own rule that only worked on those files. To create a rule for the first folder of samples, I needed to find some strings that were common between them. To do this, I opened up FileInsight and used the provided plugins Strings: a plugin that found all strings above a certain number of characters and then displayed a sorted list of the strings by length and StringsAll: a plugin that found all strings no matter the length and displayed them without sorting. 
![FileInsightSearch](/images/FileInsightSearch.PNG)

The above image shows some bookmarked sections in one of the samples I'm creating the rule for. The light blue highlighting is a bookmark created by the find functionality that comes with FileInsight, and the darker highlight is a manual bookmark that I place. These tools allowed me to create the following rule for the folder of samples:
![YaraSample1](/images/YaraSample1.PNG)

To test it, I used the windows command prompt and ran the following commands on the sample folder:
![Sample1SampleFolder](/images/Sample1SampleFolder.PNG)

and the following on the windows\system32 folder:
![Sample1System32](/images/Sample1System32.PNG)

The fact that all seven files matched without raising any false positives in system32 shows that this rule works.
To find rules for future samples, I did essentially the same as above and was able to come up with rules for those as well.

### Automating Our Analysis!
While using yara is great for small projects that require the analysis of malware, anti-malware isn't something that can be done on a reasonable time frame manually. Instead, ww would want to automate our anti-malware. The automation of anti-malware comes with the advantages of scalability, consistency, and performance concerns. However, automated anti-malware lacks the same context, is prone to evasion, and is prone to both proving and DoS/DDoS attacks. 

### What Is Cuckoo?
Through this week's material, it appears that Cuckoo creates several log files about what a process is doing. To use Cuckoo, we first renamed a malware sample to the name "bad" (the same malware from week 1's lab I believe). We then ran a program called analysis.py. This then created several chronologically ordered csv files about what the file named "bad" did.
![Cuckoo](/images/Cuckoo.PNG)

Basically, what Cuckoo is doing is waiting for a call to the Create Process API that in then hijacks. This allows it to have information that would normally difficult is access.

### Putting It All Together!
We were tasked with analyzing a folder filled with samples, determining which were clean and which were dirty, and then writing a yara signature for one of the malicious ones. I first needed to figure out which files were malicious.

File 068D5B62254DC582F3697847C16710B7 - CLEAN
That fact that it is self deleting raises some red flags, but it seems clean. All it does is access the kbdus.dll file (a file to do with the US keyboard layout), and then creates a script that deletes both the created file and the calling process.
![Sample1Cuckoo](/images/Sample1Cuckoo.PNG)

File 00670F2B9631D0F97C7CfC6C764DD9D9 - DIRTY
This file added an internet explorer icon to the desktop with a suspicious home page.
![Sample2Cuckoo](/images/Sample2Cuckoo.PNG)

File 4844FD851088A11E240CFE6B54096209 - CLEAN
This file is a program called LADS by Frank Heyne. While it's weird that it instantly deletes itself when ran normally, it is totally safe.

File A1874F714F7A15399B9FAE968180B303 - DIRTY
The file almost instantly deleted itself upon running Cuckoo. When looking through the logs generated, it looks like a file named print.exe was created in the temp file. There was also a new .dll file generated as well as this new .png file:
![InterestingPicture](/images/InterestingPicture.PNG)

Now I need to pick a dirty sample and figure out what it does in depth...
File 00670F2B9631D0F97C7CfC6C764DD9D9 adds an internet explorer icon to the user's desktop after it is ran. This is because the program has also changed the internet homepage. What this does is whenever you run internet explorer, you are sent to a malicious website with no time to react. With the running of this program, several files are created. First, a file called Dx.bat is created that copies bad.exe to c:\qusla.exe. This file also added a registry key.
![HiddenAttrib](/images/HiddenAttrib.PNG)

Then, a file named text.txt is created whose contents seems to be the end of the malicious homepage's url.
![TextFile](/images/TextFile.PNG)

A file named R000000000012.clb is also created, but I have no idea what it does.
![CLB](/images/CLB.PNG)

Using FileInsight on 00670F2B9631D0F97C7CfC6C764DD9D9 also revealed references to hau.exe and msns.exe as well as several questionable URLs.
![Websites](/images/Websites.PNG)
![EXEs](/images/EXEs.PNG)

In order to find the malware sample easier in the future, I made the following yara signature:
![Hau](/images/Hau.PNG)

These were tested on several files and only matched with the original malware sample.

### Citations
Much of the information on this blog post is provided by the Malware Defense slides created by Craig Schmugar.

----------------------------------------------------------------------------------------------------------------------------------------

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
* Incident response team preparation: The team must be prepared for an incident at any time.
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
I'm still working through several of the follow alongs, it's been a busy week. I'll hopefully have better information to add next week!

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





