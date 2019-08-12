# CS373 Summer Write-Up Blog
 
This blog is being done as an ongoing weekly homework assignment for OSU's online CS373 course. It will follow my learning as the course progresses and, hopefully, show my growth throughout the term.

## Week 7 Write-Up: Web Security
Week seven showed off the evil side of computer security so that we, the students, better understand what we're up against. 

### What is a Web Delivery Mechanism?
A web delivery mechanism is basically any web-based malware delivery system. Things from phishing to plug-in exploits all fall under the unbrella term of web delivery mechanism. With the understandably immense popularity that the web has, it's estimated that 95% of all malware is delivered to victims through the web. There are several different kinds of web-based malware delivery:
* Phishing: An attempt to illegally attain sensitive information
* Cross-site scripting: The injection of scripts that can affect other users on an otherwise trustworthy web service.
* Browser exploitation: Malicious code that takes advantage of vulnerabilities found in the browser application.
* Plug-in exploitation: Malicious code that takes advantage of vulnerabilites found in popular browser plug-ins like flash player.
* MitB: A trojan that manipulates transactions that take place within the browser.

### How Does The Code Get Injected?
There are several different injection points in the browser that can be used by malicious code:
* De-obfuscated Content: The rendered content is changed in some way.
* JavaScript: Modifying scripts going in and out of the browser.
* HTML DOM Tree: Attacked through the browser or its extensions.
* Raw HTML: Intercepting content and changing it.
* HTTP: An attack directly on the network.

### What is a User-Level Attack?
A user-level attack is an attack on the end user rather than any sort of technological attack. As humans, we are all at risk of psychological manipulation, add in the fact that we are quick to click on pretty much anything we see makes it understandable that this is a good avenue for attack.

### What is Social Engineering?
Social engineering is the manipulation of people in order to fulfill some malicious intent. For example, if you've ever gone to a website to download something and seen adverts with "Download Here!" plastered all over them, you've witnessed an example of social engineering. If you weren't paying attention, you would have downloaded some unwanted, and potentially malicious, software! As the lecturer of the week put it "I mean, people will install malware completely on their device and pay $29 to get it removed." 

### How Are User-Level Attacks Performed?
User level attacks exploit common character traits that users exhibit:
* Impatience
* Laziness
* Self-proclaimed omniscience (I know what I'm doing!)
* Clickaholicism (I can't stop clicking on everything)
There are several different methods for performing these manipulative attacks:
* Phishing: Fake URLs that ask for sensitive information that the normal website would ask for.
* Fake Anti-Virus software: Mimics a legitimate anti virus software.
* Fake Updates: Mimics a legitiamte software or OS update.
* Forum Links: Phishing using forums as the delivery mechanism.
* Search engine optimization poisoning: Gaming search engines to direct users to malicious content.
* Social Media Links: Getting information through social media that you probably shouldn't have.
* Malvertising: Fake advertisments that redirect to a malicious link.
These methods cause users to unknowingly infect themselves by purposefully downloading the malicious content. This is done through the usage of executables, browser exploits, and malicious forms.

### How Do We Protect Ourselves Against User-Level Attacks?
There are several ways that we protect ourselves from attack:
* URL Reputation Systems: Real-time protection and search link annotation.
* Site Certification Services
* Client and Gateway Anti-Virus/Anti-Malware
* URL Shorteners
* Content provider education
* End user education: The holy grail, both amazing and nearly impossible.

### What is a Browser-Level Attack?
A browser level attack is any attack performed through an internet browser. Be it Firefox, Google Chrome, or Internet Explorer, all browsers are vulnerable to many different exploits. A browser can download, render, and execute maliciously crafted web content. This malicious web content exploits various vulnerabilities in  the browser. This process involves luring the user to the site, exploiting the browser, and then downloading and executing the actual payload the attacker wants to offload. This payload can be any type of malware, not just web-centric malicious content.

### What is Malware Obfuscation?
Malware obfuscation is what makes filtering page content for malicious looking code very difficult. This is done by renaming script variables to nonsense names, the removal of whitespace, using self-generating code, the usage of eval statements, and various encryption techniques.

### How are Browser-Level Attacks Performed?
There are several different types of attacks that can be performed on the browser:
* Man in the middle attacks: Intercepting and modifying network traffic.
* Man in the browser attacks: Intercepting and modifying network traffic from within the browser.
* DNS spoofing: Serving the wrong IP for the right web address.
* Clickjacking: Tricking the user into clicking the wrong thing by hiding it behind legitimate content.
* SQL injection: Circumventing authorization and revealing private data in database backed sites.
* Cross-site scripting: Exploting a browser's trust in a site to execute malicious scripts.
* Cross-site request forgery: Exploit the server's trust in the browser to execute malicious code against the browser.

### The Tools We Used!
For performing our basic attacks and analysis for the labs that we had this week, we were given hands on practice for a couple of pretty neat tools:
* BurpSuit:
* WebScarab:

For protecting the users against all this web-based malware, we were shown (but didn't get to use) several other tools with pictures provided from the lecture:
* Alexa: Used to determine general site prevalence

![Alexa](/images/Alexa.png)

* Archive.org: Used to determine site changes over time (doesn't work for short-lived malware content)

![Archive](/images/Archive.png)

* IPVoid: A blacklisted IP search

![IPVoid](/images/IPVoid.png)

* CheckShortURL: A URL expander
![CheckShortURL](/images/CheckShortURL.png)


* SiteDossier: General site information

![SiteDossier](/images/SiteDossier.png)

* Webutation: URL reputation checker

![Webutation](/images/Webutation.png)

* Web Inspector: A scanning tool that also features recently detected malicious websites

![WebInspector](/images/Web Inspector.png)

* Virus Total: Another web scanning tool

![VirusTotal](/images/Virus Total.png)

* Linux JWhois: A domain registration data client

![LinuxJWhois](/images/Linux JWhois.png)

* Linux Dig: Domain Name System(DNS) resolver tool

![LinuxDig](/images/Linux Dig.png)

* Indicators of Compromise: provides contextual data about malicious objects

![IndicatorsofCompromise](/images/Indicators of Compromise.png)

### Citations
Much of the information on this blog post is provided by the Network Security powerpoint slides and created by Cedric Cochin.

----------------------------------------------------------------------------------------------------------------------------------------

## Week 6 Write-Up: Network Security
Week six covered threats that can attack networks and the measures taken to protect against them. We were given, as with almost any other week, new tools to aid in our discovery of this field of technological security. These tools allowed us to catch network traffic to and from our system in real time.

### Why Do We Need Network Security?
Network Security is used to help with the protection of hosts. This is done by keeping dangerous hosts out, preventing data theft and loss, and hiding network traffic. Several threats are also directed directly at networks. These include Distributed Denial of Service (DDoS) attacks as well as attacks directly to the network. Some networks are threats all on there own. These include worms, botnets, resource theft, and infrastucture damage.

### How Do We Protect The Network?
To protect a network, we use several key tools and strategies:
* Positive policy: A synonym for whitelisting. Allowing somethings onto the network while disallowing other things.
* Firewalls / Security Zones: Filters (firewalls) being used for network traffic between zones. Gateways are another way of filtering traffic.
* Defense in Depth: Layering the defenses upon itself until you have a nigh impenatrable fortress of network security.
* Intrusion Detection: Detecting anomalies to determine whether or not you are being attacked
* Honeynets / Intrusion Deception: Provide attackers with a dummy network that wastes their time.
* Quarantine: If a host is dangerous, prevent it from transfering traffic with any other machines.
* Reputation: Use a library of things and cross-reference it to determine if something is good or bad.
Every technique comes with its own set of advantages and disadvantages.

### How Do We Get Attacked?
There are several different kinds of attacks that could possibly target a network:
* Man in the Middle (MITM): An attack where one person (the man in the middle) can intercept, direct, and manipulate data sent between two hosts. When used for evil, MITM attacks can lead to ARP poisoning where someone floods a netowkr with arp messages, or TCp hijacking where data in a tcp stream is manipulated in some way. When used for good, MITM can be used to terminate TCP procies, SSL manipulation, and the preventinon of questionable data being on sites and servers.
* Hidden Data Transmissions: An attack where data is transmitted through unintended channels to remain undetected. Examples of this legitmate channel misuse include hiding in plain sight, payload tunnerling, overlapping IP segments, data at the end of a datagram or file, and steganography. 
* Resource Consumption Attacks: Attacks such as DoS or DDoS that are designed to consume resources and ensure a targeted service becomes unusable. The types of DoS methods include network exhaustion, cpu exhaustion, memory exhaustion, storage exhaustion, application vulnerability exploitation, and other finite resource exploits.
* Bugs and Backdoors: Design flaws that allow for compromise. These compromises include built-in or default passwords, packet bombs, protocol design bugs, and buffer overflow.

### How Do Attackers Know What To Attack?
When an attacker wants to attack a machine, they must first know of that machine's existance. They do this by performing reconnaissance. There are two kinds of reconnaissance:
* Active Reconnaissance: scanning for hosts using simple commands like ping and then scanning for vulnerabilities.
* Passive Reconnaissane: The generally illegal act of gather data using equipment, passive mapping of services, and content like web pages and e-mails.

### Can We Defend Against Reconnaissance?
Not particularly. Policy and deep inspection, along with honenets, can help slow down active reconnaissance. The only ways to slow down passive reconnaissance is the usage of physical security or cryptography.

### The New Tool!
We were provided with a new tool in order to help us better understand network security. This tool was WireShark:
![WireShark](/images/WireShark.PNG)

Along with wireshark, we were given some scripts we had to write alongside this great tool in order to help better our understanding of network analysis.

### The Robustness Principle!
This week, we've been asked to review a document and express our agreement and disagreement with the statements it is making. There really isn't anything I don't agree with in the principle. In software engineering I and II, we were taught the idea that software we create must be open to change and ready for anything. This idea shown to us in these software engineering courses seems incredibly similar to that of the robustness principle by Jonathan Postel. It so similar that it may be the inspiration for it. The majority of the document represent the same ideas; however, the last one strays a tiny bit. Instead of staying on the same spiel, the author starts talking in a way very similar to Occams Razor, the idea that the simplist solution is more than likely the best. If the software isn't simple, it breaks the previous rule and is no longer adaptiable and open to change.
![Robustness](/images/Robustness.PNG)

### Firewall Policy Sheet!
This week, along with the robustness principle exercies, we were also asked to create the policy for a zone diagram provided to us. I did my best, but I really didn't have much of a clue as to what I was doing:
![Firewall](/images/Firewall.PNG)

### Citations
Much of the information on this blog post is provided by the Network Security powerpoint slides and exercises created by Ram Venugopalan and Geoffrey Cooper.

----------------------------------------------------------------------------------------------------------------------------------------

## Week 5 Write-Up: Windows Memory Manipulation
Week five covered the manipulation of Windows memory in order to hide malicious files. More specifically, the week covered the definition, purpose, and detection of techniques used to hide malicious files. To aid in our task of finding difficult to detect changes to the system, we were once again introduced to several new tools. What's interesting about this week's tools is their similarity to some tools we've already been introduced to. This week was, while difficult to understand, short and sweet so there's not much to write about.

### What is a Rootkit?
A rootkit is, put simply, malware that hides itself and its actions and makes it difficult to detect. This means that malicious code can be activated on a machine without substantial fear of being detected by users and any saftey measures put in place on the system. The most common method of hiding employed by rootkits is a technique known as hooking.

### What is Hooking?
Hooking is the hijacking of messages for use in ways other than the intended usage. For example, when a rootkit changes the functinality of an operating system function call in order to hide itself from outside view, that is hooking. While generally used for innocent things like debugging software or benchmarking programs, it is also the main method that rootkits use to hide their existance.

### How Do We Detect Unwanted Hooking?
When a function is hooked onto, it changes pointer values in order to execute or skip the code it wants. An aspiring anti-virus software would periodically check the pointers and make sure that the correct memory addresses are being stored in them. If they're not, then we know a program is using the hooking technique.

### What Is A Bootkit?
Bootkits are similiar to rootkits in that they are one of several types of malware that attempt to hide themselves on a system. Bootkits generally attack the Master Boot Record (occasionally they attack other parts of the system boot process as well) in order to manipulate the system in the way they want. Since a bootkit gets run before the kernel does, a bootkit has significantly more power over a system than a rootkit relying on kernal power does.

### What Tools Do We Use?
In order to help the process of traversing Windows memory, we were introduced to several new tools.  These tools were:
* WinDBG remote: Provides a method of using WinDBG on a remote system.

![WinDBGRemote](/images/WinDBGRemote.PNG)

* Tuluka: A program written by a malware researcher to aid in the analysis of rootkits.

![Tuluka](/images/Tuluka.PNG)

* Process Hacker: A program similar to that of process explorer with both read and write functionality.

![ProcessHacker](/images/ProcessHacker.PNG)

* LiveKD: Provides a read-only view of kernel memory of a running process.

![LiveKD](/images/LiveKD.PNG)

### Citations
Much of the information on this blog post is provided by the Malware Defense powerpoint slides and exercises created by Aditya Kapoor.

----------------------------------------------------------------------------------------------------------------------------------------

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

#### Lesson 1
![Lesson1Questions](/images/Lesson1Questions.PNG)

Lesson 1 allowed us to practice the basics of using WinDbg on a (for testing purposes) website. We covered simple things like what memory address certain parts get loaded at, the values of registers at certain points, and the usage of commands such as `u`, `bp`, `du poi`, and `g`. We also got a fun part where the unicode in one of the registers read "FluffyBunniesDontFlapOrQuack."

#### Lesson 2
![Lesson2Questions](/images/Lesson2Questions.PNG)

Lesson 2 is where we gain enough understanding to exploit the vulnerabilities and then attacking. We first deconstruct the vulnerable function in question and determine the data type of its inputs. Then we determine what the vulnerable data is using three methods. We "smash the stack" and overflow. I'm assuming this is done with the letter "A" as registers that are affected are the sequence of 41414141. Then, we "stomp the stack" in that we manipulate memory that is being used in a manner that conflicts with what is currently using the memory. 
![StompTheStack](/images/StompTheStack.PNG)

Then we determine the address of the function that contains the vulnerability by sending less data to the process. With this information, we then exploit by creating some changes to code.

#### Lesson 3
Lesson 3 is where we attempt to us the "use-after-free" exploit to execute memory that has already been freed. This usually results in a crash, but can be used to perform arbitrary code execution. 

### Citations
Much of the information on this blog post is provided by the Malware Defense powerpoint slides and exercises created by Brad Antoniewicz.

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





