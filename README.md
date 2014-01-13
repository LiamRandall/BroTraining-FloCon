FloCon 2014 Bro Training Syllabus:
===============

0. Setup VM
  1. COPY files from stick to USB
  2. Install VirtualBox & VirtualBox Extensions
  3. Uncompress files- 7-zip on Windows, "The Unarchiver" on Mac
  4. logon bro/bro

1. Class files
  1. /home/bro/training/
  2. Bro /opt/bro
  3. Config /opt/bro/share/bro/site/local.bro
  4. Pcaps /opt/TrafficSamples , /opt/PCAPS_TRAFFIC_PATTERNS

2. What is Bro?
  1. Bro is a language first
  2. Event-driven
  3. Built-in variables like IP address and time interval are designed for network analysis
  4. Built-in functions can be implemented in C++ for speed and integration with other tools

3. A Tour of the Bro logs
  1. ```cd training\files-framework``` 
  2. Run Bro against a PCAP: ```bro -r /opt/TrafficSamples/faf-traffic.pcap```
  3. Look at the logs generated: ```ls *.log```
  4. Go through some of the logs (e.g. cat files.log | colorize); intro to log guides
  5. Let's enable some additional scripts: ```bro -r /opt/TrafficSamples/faf-traffic.pcap local```
  6. Comparing your history, what additional logs are generated?
  7. Notice that the contents of some of the logs have changed.
  8. Explore the configuration: ```less -S /opt/bro/share/bro/site/local.bro```

4. Exploring Logs with bro-cut
  1. Let's move into a different set of pcaps ```cd ../http-auth```
  2. Exercise: ```bro -C -r http-basic-auth-multiple-failures.pcap local```
  3. ```bro-cut``` can be used like ```sed```, ```cut```, ```awk``` all at once- with the advantage that it abstracts away from the specific schema (column order) of the logs.
  4. We can easily start to ask questions like: What is the count of the distinct status_code: ```cat http.log | bro-cut status_code | sort | uniq -c | sort -n``` 
  5. Or you could get a count of http sessions by username: ```cat http.log | bro-cut username | sort | uniq -c | sort -n```
  6. Can you generate a count of status_codes by username? What about usernames by status_code? 
  7. Now add in the distinct URI?  What do you think is going on in this pcap?
  8. Let's add a little more information and context to this pcap; let's tell Bro to extract the passwords as well: ```bro -C -r http-basic-auth-multiple-failures.pcap local http-auth-passwords.bro```
  9. Now let's explore the basic http.log again: ```less -S http.log```
  10. Do you see the populated ```password``` field?
  11. Will the ```bro-cut``` summaries you generated earlier still work?

5. Sumstats Introduction
  1. What are sumstats?  Presentation.
  2. Review [FTP Bruteforcing](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/brute-force.md) or check it locally: ```less -S /opt/bro/share/bro/policy/protocols/ftp/detect-bruteforcing.bro```
  3. Review the previous exercise- can we apply this model to detect http basic auth bruteforcing?  Suggest some methods.
  4. How many distinct measurements do we want to make?  Based on the previous example can you implement a solution?  For bruteforcers?  For the bruteforced?
  5. Review [HTTP Basic Auth Brute Forcer Solution](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/detect-http-basic-auth-bruteforcer.bro)
  6. Review [HTTP Basic Auth Server Brute Forced Solution](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/detect-http-basic-auth-server-bruteforced.bro)
  7. Execute both detections: ```bro -C -r http-basic-auth-multiple-failures.pcap local detect-http-basic-auth-bruteforcer.bro detect-http-basic-auth-server-bruteforced.bro```
  8. Discuss derivations and improvements- tracking by ASN, remote subnet, whitelisting, blacklisting
  9. Additional Demonstrations of the same technique.

6. Intel Framework
  1. Exercise 1: [Create An Intel File](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/1-create-intel.md)
  2. Exercise 2: [Notice on Intel Hits](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/2-intel-do-notice.md)
  2. Exercise 3: [Notice on Spcific Types of Intel Hits](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/3-intel-notice-on-types.md)  

7. Files Framework
  1. File extraction demo
    1. Extract files: ```bro -r /opt/TrafficSamples/exercise-traffic.pcap extract-all-files.bro```
    2. Show files: ```nautilus extract_files/```
    3. Play a video: ```totem "extract_files/"`ls -S1 extract_files | head -n 1````
  3. Writing a script, beginging with the template, can you generate a notice on a specific file type? 
    1. ```01_notice_on_mimetype_shell.bro```
    2. Solution: ````01_notice_on_mimetype.bro````
  4. Running the script: ```bro -r /opt/TrafficSamples/faf-traffic.pcap 01_notice_on_mimetype.bro```
  
8. Basic Malware  
  1. move to the malware exercises ```/home/bro/training/malware```
  2. Let's start with ```1-blackhole-medfos```
    1. Let's replay the pcap: ```bro -r blackhole-medfos.pcap local```
    1. Starting with ```conn.log``` work your way up the stack- what happens in this pcap?
    2. ```files.log``` really shortcuts the process doesn't it?
    3. ```cat notice.log``` What did bro tell you?
  3. Let's move on a bit: ```2-purplehaze-pihar```
    1. Let's begin by replaying the pcap: ```bro -r purplehaze.pcap local```  This may take a few mintues to run; be patient.
    2. Start exploring the pcaps- what is going on here?  At some level handling malware is an attempt to understand the motivations- why was this installed?
    3. This particular malware performs click fraud for the botnet owners; let's explore a bit: ```cat http.log | bro-cut referrer | sort | uniq -c | sort -n```
    4. There are a range of things we could detect here- suggestions?
    5. Let's look at some low hanging fruit- I see some new binaries coming down the wire: ```cat files.log | grep dosexec```
    6. Let's follow the stack here- take the fuid and search all of the logs for it; something like this: ```cat http.log | grep F-YOUR-ID```.  How did we know to search the http.log?
    7. Ok, we see this file come down via via http; now the ```user_agent``` field is controlled by the host, so it is easy to forge; however, here we see Java downloading a binary?!  Is that a good thing?!
    8. Let's generalize the previous case and create an alert for that behavior; explore '''cat exe-download-by-java.bro```
  3. Next on the list ```3-smokekt150``
    1. Let's start like usual: ```bro -C -r smokekt150.pcap local```
    2. Explore the log files; I see a number of potential canidates for items we could fire on.  Let's look a little deeper.  Take a look at the specified .bro file; what are we doing here?  Let's replay the pcap extracting header names and values. [script](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/extract-header-names-and-values.bro)
    3. Download this script and replay it through Bro again: ```bro -C -r smokekt150.pcap local extract-headers-names-and-values.bro```
    4. Now let's investigate the http.log a little further.  Lets look a little closer at those http header values:
    5. ```less http.log | bro-cut server_header_names server_header_values```
    6. This content type looks a little weird to me: ```text/html; charset=win-1251```
    7. Is that something we should see on our networks (I don't know, is it?)?  What is that?
```
http://en.wikipedia.org/wiki/Windows-1251
	Windows-1251 (a.k.a. code page CP1251) is a popular 8-bit character encoding, designed to cover languages that use the Cyrillic script such as Russian, Bulgarian, Serbian Cyrillic and other languages. It is the most widely used for encoding the Bulgarian, Serbian and Macedonian languages
```
    8. Is that normal for our environment?  Let's see if we can match on that.  Create a new Bro Script: ```match-cyrillic-header.bro```:

```bro
@load base/protocols/http/main
@load base/frameworks/notice

module HTTP;
 
export {
	redef enum Notice::Type += {
		## raised once per host per 10 min
		Bad_Header
	};

	global bad_header: set[addr] &create_expire = 10 min;
}
 
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
  {
     if ( name == "CONTENT-TYPE" && value == "text/html; charset=win-1251" )
     {	
	 if ( c$id$orig_h !in bad_header )
	 {
		add bad_header[c$id$orig_h];
		NOTICE([$note=HTTP::Bad_Header,
		 $msg=fmt("Bad header \"%s\" seen in %s", value,c$uid),
		 $sub=name,
		 $conn=c,
		 $identifier=fmt("%s", c$id$orig_h)]);
		

		print fmt("%s :name:value:  %s:%s",c$uid,name,value);
	 }
     }
  }```

    9. This code is overly simple; every time we see an http header key pair this event fires.  We simply look the event and are checking specifically for the Cyrillic language.
    10. Did you count how many times this header pair was transmitted in the sample?  Here we are thresholding the notice with a global variable called "bad header"; and we time hosts out using the:
    ```**&create_expire = 10** .
    global bad_header: set[addr] &create_expire = 10 min;```
    
    11. Let's go ahead and replay the sample using our new detector: ```bro -C -r smokekt150.pcap local match-cyrillic-header.bro``` 
    12. You should now see a thresholded alert in the notice.log.
  
9 Basic Tool Integration
  1. Let's head back to ```/home/bro/training/files-framework```  
  2. Walk-through ````02_run_exiftool.bro````
    1. Install exiftool.log  (this is already completed on your VMs)
 ```
 mkdir exiftool
 cd exiftool/
 wget http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-9.43.tar.gz
 tar -xzf Image-ExifTool-9.43.tar.gz
 ```
  3. Confirm ```02_run_exiftool.bro``` has the correct path: ```/home/bro/training/files-framework/exiftool/Image-ExifTool-9.43```
  4. Run ```bro -r /opt/TrafficSamples/faf-traffic.pcap local 02_run_exiftool.bro```
  5. Examine exiftool.log
  6. Discuss this integration

10. Notice Framework
  1. The notice framework is designed to give Bro operators flexibility; let's explore.
  2. Exercise: ```bro -r 01_emailing_simple.bro synscan.pcap``` 
  3. Exercise: ```bro -r 02_emailing_complex.bro synscan.pcap```
  4. Exercise: ```bro -r 03_avoid_some_scanners.bro synscan.pcap```
  5. Exercise: ```bro -r 04_create_a_new_notice.bro mbam_download.trace```
  6. Walk-through ```05_create_an_action.bro```

11. Signature Framework
  1. Bro has a capable signature engine built in; if you are familiear with traditional signature based detection / IDS's these examples should be pretty familiar.
  2. Let's head on over to: ```/home/bro/training/signature-framework```
  3. Let's warm up: ```1-mswab_yayih```
    1. Exercise: ```bro -r mswab-yahih.pcap local```
    2. What logs do you see created?  Any new ones we haven't seen before?
    3. Explore the logs, paying special attention to signature.log, notice.log, and http.log
    4. What is happening in this pcap?
    5. Find the signature file that fired?  Where would you look?
    6. Explore the signature file: ```cat /opt/bro/share/bro/policy/frameworks/signatures/detect-windows-shells.sig```
    7. Explore the file a little further; let's extract all the files: ```bro -r mswab-yayih.pcap local ../../files-framework/extract-all-files.bro```   
    8. Analyze requests/responses: ```for i in `bro-grep info.asp http.log | bro-cut orig_fuids resp_fuids | sed -e 's/\t/\n/' | grep -v '-'`; do cat "extract_files/extract-HTTP-$i"; echo; echo "-------"; done```
  4. Gotten in on the bitcoin craze yet?  Botnet operators sure have; let's check out ```2-tbot```
    1. Malware has a purpose; many times that purpose is to generate revenue for their malware authors.
    2. In this sample we're going to be looking at a bot whose aim is to deliver bitcoin mining traffic.
    3. Let's take a look: ```bro -r tbot.pcap local```
    4. Is it obvious what is going on here right away?  You may need to understand a little bit about the way bitcoin mining works; the tldr is that members generally join computational pools.  Have a large botnet?  Put it to work on some one elses electric bill!
    5. Explore ```http.log```.  What is happening here? 
    6. Do you see anything that stands out?  What appears to be going on in the http log?
    7. Now let's take a look at ```json-rpc.sig  mining.bro```
    8. Let's run this detection routine:  ```bro -r tbot.pcap local mining.bro```
    9. Check your notice.log
	10. Here we were able to build some logic around a traditional signature; let's explore more.
  5. The ```Lurk0``` family of malware has been around for a bit; there are quite a few derivatives out there.
    1. If you are note familiar with the family of malware, take a look at this great analysis of the many derivatives of this malware found in the wild: [The many faces of Gh0st Rat - Norman](http://download01.norman.no/documents/ThemanyfacesofGh0stRat.pdf)
    2. Let's figure out what a signature for the RAT might look like; explore the lurk0 subfolder: ```/home/bro/training/signature-framework/3-lurk/lurk0```
    3. There are three files- what does each one do?
    4. What are we firing on?
    5. Let's see if they work: ```bro -r lurk0.pcap local lurk0```
    6. What is the problem with signature based detection like this?
    7. Demonstration
  5. Our final signature framework, is ```4-zeroaccess```
    1. Review the included pdf.
    2. Using the template code, can you create a signature that works?
    