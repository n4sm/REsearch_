/usr/local/bin/pip3 install pefile
/usr/local/bin/pip install pefile

if python -c 'import pkgutil; exit(not pkgutil.find_loader("pefile"))'; then
    echo '[*] pefile installed !'
else
    echo '[-] pefile is not found on your system'
    echo 'Please check the configuration of pip for python3'
fi

if python -c 'import pkgutil; exit(not pkgutil.find_loader("peutils"))'; then
    echo '[*] peutils installed !'
else
    echo '[-] peutils is not found on your system'
    echo 'Please check the configuration of pip for python3'
fi
