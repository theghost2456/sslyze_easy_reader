Creator:      Martin W

Date Created: 18/06/2024



This tool is designed to make easy reading for the output of sslyze. the script will read the output file, look for key words within the results file and output the weak ciphers, certificate lifespan and mamximum life span.



to use the tool.
	
	- To use the shell script, modify the permissions with chmod. Example: 'chmod 755 sslyze.sh' this will allow it to run.
	
	- Run sslyze.sh, enter the IP address or URL, then the port number. (By default, the port number is 443)

	- Optional: use a text editor to view 'sslyze_results.txt' (nano sslyze_results.txt)
	
	- The output results if sslyze.sh is used as the input file source for ssl.py. The script will read sslyze_results.txt and spit out an easy to txt file

	- run 'python3 ssl.py'

	- Enter a file name for the output. The default output file format is always .txt
