#!/bin/bash
read -p "Введите имя нового проекта или нажмите Enter для продолжения старого: " name_pro
	if [ ${name_pro:-null} != null ];
	then
		echo $name_pro > vars/pn.txt
		echo 0 > vars/gc.txt
		echo 0 > vars/lc.txt
		echo -n > scanned_ip.txt
		mkdir results/$name_pro 2> /dev/null 
	fi


global_count=`cat vars/gc.txt`	
count=`cat vars/lc.txt`
name_pro=`cat vars/pn.txt`	
echo "Start scanning adresses..."
path_dir="$name_pro/scope_$global_count"
rm results/tmp_http.txt 2> /dev/null
rm results/tmp.txt 2> /dev/null
rm results/tmp_nuclei.txt 2> /dev/null
rm results/tmp_mysql.txt 2> /dev/null
rm results/tmp_tmp_mysql.txt 2> /dev/null
rm results/tmp_mssql.txt 2> /dev/null
rm results/tmp_tmp_mssql.txt 2> /dev/null
rm results/tmp_postgres.txt 2> /dev/null
rm results/tmp_tmp_postgres.txt 2> /dev/null
rm results/tmp_ssh.txt 2> /dev/null
rm results/tmp_tmp_ssh.txt 2> /dev/null
rm results/tmp_ftp.txt 2> /dev/null
rm results/tmp_tmp_ftp.txt 2> /dev/null 
rm results/tmp_smb.txt 2> /dev/null
rm results/tmp_tmp_smb.txt 2> /dev/null 
max_count=10 # по сколько упаковывать в файл

count_no_scan=$(cat no_scanned_ip.txt | wc -l)
count_scan=$(cat scanned_ip.txt | wc -l)
count_total=$(( $count_no_scan + $count_scan ))

while read scope_string
do
echo
echo "Scanned $global_count from $count_total"
	
	if [ $count -eq $max_count ]
	then
	global_count=$(( $global_count + 1 ))
	echo $global_count > vars/gc.txt
	path_dir="$name_pro/scope_$global_count"
	count=0
	echo $count > vars/lc.txt
	fi

count=$(( $count + 1 ))
echo $count > vars/lc.txt

echo "Scanning host $scope_string..."
echo
touch results/$path_dir.txt
echo >> results/$path_dir.txt
echo "______________Host: $scope_string ______________" >> results/$path_dir.txt
echo >> results/$path_dir.txt
echo Host: $scope_string >> results/$path_dir.txt
echo >> results/$path_dir.txt
echo "Scanning ports $scope_string ..."
timeout 600 nmap -A -n -sT --top-ports 1000 $scope_string --open | grep open >> results/tmp.txt

touch results/tmp_http.txt
cat results/tmp.txt | grep http | awk -v m=$scope_string -F "/" '{print "http://" m ":" $1}' | sed '/^#\|^$\| *#/d' >> results/tmp_http.txt 
cat results/tmp.txt >> results/$path_dir.txt
string_in_file=`wc -l results/tmp_http.txt | awk '{print $1}'` 
echo "Port scanning is done!"
echo
	
	if [ $string_in_file -gt 0 ]
		then   
			while read nuclei_string
			do
			echo "Scanning nuclei $nuclei_string ..."
			echo >> results/$path_dir.txt
			ip_port=`echo $nuclei_string | awk -F "//" '{print $2 }'`
			echo "_____Nuclei_____$ip_port _____" >> results/$path_dir.txt
			echo >> results/$path_dir.txt
			touch results/tmp_nuclei.txt
			timeout 1800 nuclei -silent -u $nuclei_string -o results/tmp_nuclei.txt 
			cat results/tmp_nuclei.txt >> results/$path_dir.txt
			rm results/tmp_nuclei.txt 2> /dev/null 
			done < results/tmp_http.txt 
			
			while read ffuf_string
			do
			echo "Fuzzing directories $ffuf_string ..."
			echo >> results/$path_dir.txt
			ip_port=`echo $ffuf_string | awk -F "//" '{print $2 }'`
			echo "_____Fuzzing_____$ip_port _____" >> results/$path_dir.txt
			echo >> results/$path_dir.txt
			touch results/tmp_ffuf.txt
			ffuf -u "$ffuf_string/HFUZZ" -c -t 100 -w wordlists/directory-list-2.3-medium.txt:HFUZZ -maxtime 1200 -fc 404 -mc all -ic -ac -of md -o results/tmp_ffuf.txt 

			string_ffuf_file=`wc -l results/tmp_ffuf.txt | awk '{print $1}'` 
			if [ $string_ffuf_file -gt 200 ]
				then   
				echo "WARNING! Use manual fuzzing!" >> results/$path_dir.txt
				else
				cat results/tmp_ffuf.txt | grep \| | awk -F "|" '{print $1, $3, $6}' >> results/$path_dir.txt
			fi

			rm results/tmp_ffuf.txt 2> /dev/null 
			done < results/tmp_http.txt 
	fi

rm results/tmp_http.txt 2> /dev/null 



touch results/tmp_mysql.txt
cat results/tmp.txt | grep mysql | awk -v m=$scope_string -F "/" '{print "-p " $1 " " m}' | sed '/^#\|^$\| *#/d' >> results/tmp_mysql.txt 
string_in_file=`wc -l results/tmp_mysql.txt | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "MySQL Detected! Deep scanning..."
		while read sql_string
		do
		echo >> results/$path_dir.txt
		ip_port=`echo $sql_string | awk '{print $3 ":" $2}'`
		echo "_____Deep Scanning MySQL_____$ip_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 1200 nmap -sV --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-query,mysql-users,mysql-vuln-cve2012-2122 $sql_string >> results/tmp_tmp_mysql.txt 
		cat results/tmp_tmp_mysql.txt | sed '1,4d' | sed '$d' | sed '$d' >> results/$path_dir.txt
		rm results/tmp_tmp_mysql.txt 2> /dev/null 
		
		done < results/tmp_mysql.txt 	
		
	fi
rm results/tmp_mysql.txt 2> /dev/null 

touch results/tmp_mssql.txt
cat results/tmp.txt | grep mssql | awk -v m=$scope_string -F "/" '{print "mssql://" m ":" $1}' | sed '/^#\|^$\| *#/d' >> results/tmp_mssql.txt 
string_in_file=`wc -l results/tmp_mssql.txt | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "MsSQL Detected! Deep scanning..."
		while read sql_string
		do
		mssql_port=`echo $sql_string | awk -F":" '{print $3}'`
		mssql_ip=`echo $sql_string | awk -F"//" '{print $2}' | awk -F":" '{print $1}'`
		echo >> results/$path_dir.txt
		echo "_____Deep Scanning MsSQL_____$mssql_ip:$mssql_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 1200 nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$mssql_port,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV  $mssql_ip >> results/tmp_tmp_mssql.txt 
		cat results/tmp_tmp_mssql.txt | sed '1,3d' | sed '$d' | sed '$d' >> results/$path_dir.txt
		rm results/tmp_tmp_mssql.txt 2> /dev/null 
		
		done < results/tmp_mssql.txt 	
		
	fi
rm results/tmp_mssql.txt 2> /dev/null 	
	
touch results/tmp_postgres.txt
cat results/tmp.txt | grep postgres | awk -v m=$scope_string -F "/" '{print "postgres://" m ":" $1}' | sed '/^#\|^$\| *#/d' >> results/tmp_postgres.txt 
string_in_file=`wc -l results/tmp_postgres.txt  | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "Postgres Detected! Checking common password..."
		while read postgres_string
		do
		echo >> results/$path_dir.txt
		ip_port=`echo $postgres_string | awk -F "//" '{print $2 }'`
		echo "_____Common password for Postgres_____$ip_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 120 hydra -L wordlists/postgres_users.txt -I -q -u -f -e n -P wordlists/postgres_pass.txt $postgres_string -o results/tmp_tmp_postgres.txt 
		cat results/tmp_tmp_postgres.txt | sed '1d' >> results/$path_dir.txt
		rm results/tmp_tmp_postgres.txt 2> /dev/null 
		
		done < results/tmp_postgres.txt 	
		
	fi
rm results/tmp_postgres.txt 2> /dev/null 

touch results/tmp_ssh.txt
cat results/tmp.txt | grep ssh | awk -v m=$scope_string -F "/" '{print "ssh://" m ":" $1}' | sed '/^#\|^$\| *#/d' >> results/tmp_ssh.txt 
string_in_file=`wc -l results/tmp_ssh.txt | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "SSH Detected! Brutforce..."
		while read ssh_string
		do
		echo >> results/$path_dir.txt
		ip_port=`echo $ssh_string | awk -F "//" '{print $2 }'`
		echo "_____Bruteforce SSH_____$ip_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 1200 hydra -L wordlists/ssh_users.txt -I -q -t 4 -u -f -e n -P wordlists/ssh_pass.txt $ssh_string -o results/tmp_tmp_ssh.txt 
		cat results/tmp_tmp_ssh.txt | sed '1d' >> results/$path_dir.txt
		rm results/tmp_tmp_ssh.txt 2> /dev/null 
		
		done < results/tmp_ssh.txt 	
		
	fi
rm results/tmp_ssh.txt 2> /dev/null 



touch results/tmp_ftp.txt
cat results/tmp.txt | grep ftp | awk -v m=$scope_string -F "/" '{print "ftp://" m ":" $1}' | sed '/^#\|^$\| *#/d' >> results/tmp_ftp.txt 
string_in_file=`wc -l results/tmp_ftp.txt | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "FTP Detected! Checking and Brutforcing..."
		while read ftp_string
		do
		ftp_port=`echo $ftp_string | awk -F":" '{print $3}'`
		ftp_ip=`echo $ftp_string | awk -F"//" '{print $2}' | awk -F":" '{print $1}'`
		touch results/tmp_tmp_ftp.txt 
		echo >> results/$path_dir.txt
		echo "_____Check FTP_____$ftp_ip:$ftp_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 600 nmap -sV -p $ftp_port --script ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 $ftp_ip >> results/tmp_tmp_ftp.txt 
		cat results/tmp_tmp_ftp.txt | sed '1,4d' | sed '$d' | sed '$d' >> results/$path_dir.txt
		rm results/tmp_tmp_ftp.txt 2> /dev/null 
		
		
		echo >> results/$path_dir.txt
		echo "_____Bruteforce FTP_____$ftp_ip:$ftp_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 600 hydra -L wordlists/ftp_users.txt -I -q -u -f -e n -P wordlists/ftp_pass.txt $ftp_string -o results/tmp_tmp_ftp.txt 
		cat results/tmp_tmp_ftp.txt | sed '1d' >> results/$path_dir.txt
		rm results/tmp_tmp_ftp.txt 2> /dev/null 
		
		done < results/tmp_ftp.txt 	
		
	fi
rm results/tmp_ftp.txt 2> /dev/null 



touch results/tmp_smb.txt
cat results/tmp.txt | grep smb | awk -v m=$scope_string -F "/" '{print "-p " $1 " " m}' | sed '/^#\|^$\| *#/d' >> results/tmp_smb.txt 
string_in_file=`wc -l results/tmp_smb.txt | awk '{print $1}'` 
echo
	
	if [ $string_in_file -gt 0 ]
		then   
		echo "SMB Detected! Checking..."
		while read smb_string
		do
		touch results/tmp_tmp_smb.txt 
		echo >> results/$path_dir.txt
		ip_port=`echo $smb_string | awk '{print $3 ":" $2}'`
		echo "_____Checking SMB_____$ip_port _____" >> results/$path_dir.txt
		echo >> results/$path_dir.txt		
		timeout 1200 nmap --script smb-double-pulsar-backdoor,smb-enum-shares,smb-os-discovery,smb-protocols,smb-psexec,smb-security-mode,smb-server-stats,smb-vuln-conficker,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-webexec,smb-webexec-exploit,smb2-capabilities,smb2-security-mode,smb2-vuln-uptime $smb_string >> results/tmp_tmp_smb.txt 
		cat results/tmp_tmp_smb.txt | sed '1,4d' | sed '$d' | sed '$d' >> results/$path_dir.txt
		rm results/tmp_tmp_smb.txt 2> /dev/null 
		
		
		done < results/tmp_smb.txt 	
		
	fi
rm results/tmp_smb.txt 2> /dev/null 





rm results/tmp.txt 2> /dev/null 

echo "Host $scope_string was scanned. Report was generated."
sed '1!d' no_scanned_ip.txt >> scanned_ip.txt
sed -i '1d' no_scanned_ip.txt

done < no_scanned_ip.txt
echo "Scanning is done succesfully"
