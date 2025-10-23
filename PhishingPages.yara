import "vt"

rule Kimsuky_Login_Pages_HTML { // Looks for unobfuscated Kimsuky Login Pages
    meta:
        source1 = "https://github.com/mackrose14/22T11/blob/main/index.html"
        source2 = "https://github.com/mackrose14/nomail229/blob/main/index.html" //Deobfuscated
        author = "Apodixis"
        date = "SEP2025"
        description = "Kimsuky often creates credential harvesting malware that masquerades as legitimate login pages"
        threat_actor = "Lazarus Group"
        target_entity = "file"

    strings:
        $enc1 = /var [a-zA-Z\_\-]{1,30} ?\= ?atob\([\`\'\"][a-zA-Z0-9\/\+\=]*[\`\'\"]\)/ 
        $ajax1 = /\$\.ajax\(\{\)/
        $ajax2 = /type\: [\`\'\"]POST[\`\'\"]/
        $ajax3 = /url\: [a-zA-Z0-9]{1,20}/
        $ajax4 = /crossDomain\: [Tt][Rr][Uu][Ee]/
        $ajax5 = /data\: \$\([\`\'\"][a-zA-Z0-9]{1,20}[\`\'\"]\)\.serialize\(\)/
        $AJAX = /\$\.ajax\(\{type\:\\[\`\'\"][Pp](OST|ost)\\[\`\'\"]\, ?url\:\w\, ?crossDomain\:\!0\, ?data\:\$\(\\[\`\'\"]form\\[\`\'\"]\)\.serialize\(\)\, ?beforeSend\:function\(\w\)/

        $emailSlice1 = /var [a-zA-Z0-9]{1,20} ?\= ? [a-zA-z0-9\-\_]{1,20}\.substr\({1,5}ind ?\+ ?\d\){1,5}/
        $emailSlice2 = /var [a-zA-Z0-9]{1,20} ?\= ? [a-zA-z0-9\-\_]{1,20}\.substr\(0\, [a-zA-z0-9\-\_]{1,20}\.indexof\({1,5}[\`\'\"]\.[\`\'\"]\){1,5}/

        $rcmUser = /<input class\=\\[\'\"][\w\- ]*\\[\`\'\"] id\=rcm[lL]ogin[uU]ser ?name\=rcm[lL]ogin[uU]ser placeholder\=[eE]\-?mail required type\=[eE]mail>/
        $rcmLogin = /<input class\=\\[\'\"][\w\- ]*\\[\`\'\"] id\=rcm[lL]ogin[pP]wd ?name\=rcm[lL]ogin[pP]wd placeholder\=[pP]assword required type\=[pP]assword>/

    condition:
        vt.metadata.new_file and (all of ($ajax*) or ($AJAX)) and (all of ($emailSlice*) or all of ($rcm*)) and all of ($enc*)
}

rule Kimsuky_Obfuscated_Login_Pages__HTML {
    meta: // Looks for Obfuscated Kimsuky Login Pages
        source1 = "https://github.com/mackrose14/nomail229/blob/main/index.html"
        author = "Apodixis"
        date = "SEP2025"
        description = "Kimsuky often creates credential harvesting malware that masquerades as legitimate login pages"
        threat_actor = "Lazarus Group"
        family = "N/A"
        variant = "N/A"
        target_entity = "file"

    strings:
        $obfOne1 = /\}\(\)\, \w ?\= ?\w ?\=\> ?document\.write\(\w\)\, ?\w ? \= decodeURI\([\`\'\"]{2}\.concat\([\`\'\"][\w\!\@\#\$\%\^\&\*\(\)\-\_\=\+\\\/\?\.>\,<\:\;\']*\"\){2}\.split\([\`\'\"]{2}\)/
        $obfOne2 = /\w ?\= ?\w\.length ?\% ?\w\.length\, ?\w ?\= ?\w\.length ?\- ?\d{1,2}\; ?\w ?\>\= ?0; ?\w\-{2}\) ?\w\-{2}\, ?\-1 ?\={2} ?\w ?&{2} ?\(\w ?\= ?\w\.length ?\- ?\d{1,2}\)\, ?\w ?\= ?\w ?\+ ?\w\[\w\]\, ?\w ?\>\= ?\w\.length ?\|{2} ?\(\w ?\= ?\w\[\w\]\, ?\w ?\= ?\w\[\w\]\, ?\w\[\w\] ?\= ?\w\, ?\w\[\w\] ?\= ?\w\)\;/
        $obfOne3 = /\(\w ?\=\ ?\w\, ?\w ?\= ?[\`\'\"]{2}\, ?\w ?\= ?0\; ?\w ?\< ?\w\.length\; ?\w\+{2}\) ?\w ?\+\= ?\w\[\w\]\;/
        $obfOne4 = /for ?\(\w ?\= ?[\`\'\"][\w\!\@\#\$\%\^\&\*\(\)\-\=\+\{\}\[\]\;\:\'\"\,<\.>\/\?]{10,128} ?\w ?\= ?new Array\(\w\.length\)\, ?\w ?\= ?0\; ?\w ?\< ?\w\.length\; ?\w\+{2}\) ?\w\[\w\] ? \= ?\w\.charCodeAt\(\w\)\;/

    condition:
        vt.metadata.new_file and all of ($obfOne*)
}

rule Kimsuky_Login_Pages_HTML_Mimic_Email_Domain { // Some Kimsuky Login Pages mimic the domain of the submitted email address
    meta: // Looks for Obfuscated Kimsuky Login Pages that use email address to mimic company domains
        source1 = "https://github.com/mackrose14/12387Tr33/blob/main/next.js"
        author = "Apodixis"
        date = "SEP2025"
        description = "Kimsuky often creates credential harvesting malware that masquerades as legitimate login pages"
        threat_actor = "Lazarus Group"
        family = "N/A"
        variant = "N/A"
        target_entity = "file"

    strings:
        //Extracts email address
        $email1 = /const \w{1,20} ?\= ? new URLSearchParams\(window\.location\.search\)\;/
        $email2 = /const \w{1,20} ?\= ?urlParams\.get\([\`\'\"][a-zA-Z]{3,10}[\`\'\"]\)/
        $email3 = /const ?\w{1,20} ?\= ?atob\(\w{1,20}\)\;/

        //Extracts company Name from email address
        $company1 = /const \w{1,30} ?\= ? \w{1,20}\.split\([\`\'\"]\.[\`\'\"]\)\[0\]/
        $company2 = /const \w{1,30} ?\= ? \w{1,20}\.charAt\(0\)\.toUpperCase\(\) ?\+ ?\w{1,20}\.slice\(1\)/

        //Extracts Company Domain's HTML Content for Reuse
        $domain1 = /const \w{1,20} ?\= ?document\.getElementById\([\`\'\"]\w{1,20}[\`\'\"]\)/
        $domain2 = /\w{1,20}\.src ?\= ?[\`\'\"]https?\:\/\/\$\{\w{1,20}\}[\`\'\"]/

        $telegramBot = /const \w{1,20} ? \= ?[\`\'\"]https?\:\/\/api\.telegram\.org\/bot\$\{\w{1,20}\}\/sendMessage[\`\'\"]/ //Code exfiltrates host-submitted credentials to a Private chat on Telegram
        $ipify1 = /const \w{1,20} ?\= ?await fetch\([\`\'\"]https?\:\/\/api\.ipify\.org\?format\=json[\`\'\"]\)/ //sends request to api.ipify.org (pausing execution until returned)/
        $ipify2 = /const \w{1,20} ?\= ?await \w{1,20}\.json\(\)/ //Fragment of code that uses the response from $ipify1 to extract the host IP address

        //Login Page Elements with Korean Text
        $krWebEl1 = /document\.getElementById\([\`\'\"][\w\-]{5,20}[\`\'\"]\)\.textContent ?\= ?[\`\'\"]ë¡œê·¸ì¸[\`\'\"]/ //로그인 = login
        $krWebEl2 = /document\.getElementById\([\`\'\"][\w\-]{5,20}[\`\'\"]\)\.textContent ?\= ?[\`\'\"]ë©”ì¼ í¬í„¸[\`\'\"]/ //메일 포털 = Mail Portal
        $krWebEl3 = /document\.getElementById\([\`\'\"][\w\-]{5,20}[\`\'\"]\)\.textContent ?\= ?[\`\'\"]ì´ë©”ì¼ ë˜ëŠ” ì „í™”[\`\'\"]/ //이메일 또는 전화 = Email or Phone

    condition:
        vt.metadata.new_file and (
            (all of ($email*) and 1 of ($company*) and 1 of ($domain*)) or (
                $telegramBot and all of ($ipify*)) or (
                    all of ($krWebEl*) and $telegramBot))
}

rule Kimsuky_Login_Pages_TSX {
    meta:
    source1 = "https://github.com/marksantiago02/facebook-phishing-next/commit/7e8075c4e7f0f1cfef0a114b284bf33311472866"
    author = "Apodixis"
    date = "SEP2025"
    description = "Kimsuky often creates credential harvesting malware that masquerades as legitimate login pages"
    threat_actor = "Lazarus Group"
    family = "N/A"
    variant = "N/A"
    target_entity = "file"

    strings:
    // Selects for URLs contacted to harvest a victim's host IP address and to collect IP location data
    $ipInfo1 = /const [a-zA-Z0-9]{1,10} ?\= ?await axios\.get\([\`\'\"]https?\:\/\/api\.ipify\.org\/?format\=json[\`\'\"]\)/
    $ipInfo2 = /const [a-zA-Z0-9]{1,10} ?\= ?await axios\.get\([\`\'\"]https?\:\/\/ip\-api\.com\/[a-zA-Z0-9]{1,20}\/.*[\`\'\"]\)/

    // Patterns related to the use of the Telegram API to exfiltrate user data
    $telegramSend = /await axios\.post\([\`\'\"]https?\:\/\/api\.telegram\.org\/bot\$\{[a-zA-Z0-9]{1,20}\}\/sendMessage[\`\'\"]\, ?\{/

    // URL Redirect to confuse victim and potentially hide that credential theft has occurred
    $redirect = /window\.location\.href ?\= ?/

    condition:
        vt.metadata.new_file and any of ($ipInfo*) and any of ($telegram*) and $redirect
}

rule Kimsuky_Login_Pages_base64_URLs { // Looks for communication with URLs previously observed in Kimsuky Login Page Specimens
    meta:
        source1 = "https://github.com/mackrose14/nomail229/blob/main/index.html"
        author = "Apodixis"
        date = "SEP2025"
        description = "Kimsuky often creates credential harvesting malware that masquerades as legitimate login pages"
        threat_actor = "Lazarus Group"
        family = "N/A"
        variant = "N/A"
        target_entity = "file"

    strings:
        $url1 = "https://maxmeet.online/wb-web/xend.php"


    condition:
        vt.metadata.new_file and any of them
}