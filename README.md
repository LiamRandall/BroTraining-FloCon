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
  
  
9 Basic Tool Integration  
  1. Walk-through ````02_run_exiftool.bro````
    1. Install exiftool.log 
```
mkdir exiftool
cd exiftool/
wget http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-9.43.tar.gz
tar -xzf Image-ExifTool-9.43.tar.gz
```
  2. Modify ```02_run_exiftool.bro``` with the correct path: ```/home/bro/training/files-framework/exiftool/Image-ExifTool-9.43```
  3. Run ```bro -r /opt/TrafficSamples/faf-traffic.pcap 02_run_exiftool.bro```
  4. Examine exiftool.log

8. Notice Framework
  1. Exercise: ```bro -r 01_emailing_simple.bro synscan.pcap``` 
  2. Exercise: ```bro -r 02_emailing_complex.bro synscan.pcap```
  3. Exercise: ```bro -r 03_avoid_some_scanners.bro synscan.pcap```
  4. Exercise: ```bro -r 04_create_a_new_notice.bro mbam_download.trace```
  5. Walk-through ```05_create_an_action.bro```
10. Signature Framework
  1. Exercise: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap local```
  2. With file extraction: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap site/local.bro extract-all-files.bro```   
  3. Analyze requests/responses: ```for i in `bro-grep info.asp http.log | bro-cut orig_fuids resp_fuids | sed -e 's/\t/\n/' | grep -v '-'`; do cat "extract_files/extract-HTTP-$i"; echo; echo "-------"; done```
  4. blackhole-medfos
    1. Let's get started with a couple of warm up exercises.  Blackhole is one of the most common and frequently updated exploit kits around.  Let's see what they look like with Bro's new File Analysis Framework.
	2. How many executable files were downloaded to the host?
    3. ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/CRIME/blackhole-medfos
EK_BIN_Blackhole_leadingto_Medfos_0512E73000BCCCE5AFD2E9329972208A_2013-04.pcap local```
    4. How many executable files were downloaded?
	5. ```less files.log | grep "application" | wc -l```
	6. What notices were fired?
    7. ```less notice.log```
  5-smokekt150
    1. We have Bro identifying signatures in ports and protocols that it understands; in this example, we are going to have Bro key on a specific protocol related feature.
    2. Let's replay the sample with Bro: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/CRIME/EK_Smokekt150\(Malwaredontneedcoffee\)_2012-09.pcap local```
	3. Explore the log files; I see a number of potential canidates for items we could fire on.  Let's look a little deeper.  Take a look at the specified .bro file; what are we doing here?  Let's replay the pcap extracting header names and values. [script](https://github.com/LiamRandall/BroTraining-FloCon/blob/master/extract-header-names-and-values.bro)
    4. Now let's investigate the http.log a little further.  Lets look a little closer at those http header values:
    5. ```less http.log | bro-cut server_header_names server_header_values```

This content type looks a little weird to me..

			text/html; charset=win-1251

What is that?
```
http://en.wikipedia.org/wiki/Windows-1251
	Windows-1251 (a.k.a. code page CP1251) is a popular 8-bit character encoding, designed to cover languages that use the Cyrillic script such as Russian, Bulgarian, Serbian Cyrillic and other languages. It is the most widely used for encoding the Bulgarian, Serbian and Macedonian languages
```
Is that normal for our environment?  Let's see if we can match on that.

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
  }
```

This code is overly simple; every time we see an http header key pair this event fires.  We simply look the event and are checking specifically for the Cyrillic language.

Did you count how many times this header pair was transmitted in the sample?  Here we are thresholding the notice with a global variable called "bad header"; and we time hosts out using the **&create_expire = 10** .
    global bad_header: set[addr] &create_expire = 10 min;
    
Let's go ahead and replay the sample using our new detector.

	bro -r EK_Smokekt150\(Malwaredontneedcoffee\)_2012-09.pcap local  ../solutions/match-headers.bro 

You should now see a thresholded alert in the notice.log.



4. SSL/TLS
  1. Exercise: bro -C -r rsasnakeoil2.cap
  2. Exercise: bro -r basic-gmail.pcap

