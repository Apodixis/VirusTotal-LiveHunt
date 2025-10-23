import "vt"

rule File_Contacts_Beavertail_Ferret_URL { // Looks for commonly observed domain name constructions that corresponds with the BeaverTail + Ferret infection chain
    meta:
        author = "Apodixis"
        date = "MAR2025"
        description = "Contagious Interview malware frequently reuses malicious domain page structures"
        threat_actor = "Lazarus Group"
        family = "BeaverTail / FERRET"
        variant = "N/A"
        target_entity = "file"

    condition:
        for any vt_behaviour_http_conversations in vt.behaviour.http_conversations: (
            vt.metadata.new_file and (vt_behaviour_http_conversations.url matches /https?:\/\/[\d\.]+:\d{2,5}\/(pdown|pay(l|load)?|m?clip|mclip?|(br?ow)|(brow?)|client\/\d)+\/(.*)/i
            or vt_behaviour_http_conversations.url matches /https?:\/\/[\d\.]+:12[24]4\/(p?down|keys?|pay(l|load)?|uploads|m?clip|mclip?|(br?ow)|(brow?)|client\/\d)+\/(.*)/i
            )
        )
} // split page matches to only include /uploads and /keys when matching frequently used ports (1224 and 1244)

rule Beavertail_Ferret_pdown { //file commonly used in BeaverTail install to provide necessary dependencies to FERRET samples
    meta:
        author = "Apodixis"
        date = "MAR2025"
        description = "pdown is a python wheel commonly downloaded by BeaverTail to install dependencies for [VARIANT]Ferret payloads. Searching for files similar to pdown to identify new BeaverTail samples"
        threat_actor = "Lazarus Group"
        family = "FERRET Malware"
        variant = "N/A"
        target_entity = "file"

    strings:
        $Vhash1 = "861abbe80b2e497a57dfaec1a260b4d5"
        $SSDEEP1 = "1572864:6mIiGkgmsKpC0Xn1OoG4JC6B9O1jPIaG7YiC2:Y0XHRB9OZJG7YiC2"
        $TLSH1 = "T1DFB72313C29D4275DB872F38218A5327D86CEF64B3616BE73EB41E58EC92B84874B705"
    
    condition:
        vt.metadata.new_file and any of them
}

rule Beavertail_Ferret_content_matches { //searches for longer strings associated with ContagiousInterview malware
    meta:
        author = "Apodixis"
        date = "JUN2025"
        description = "BeaverTail and Ferret family malware frequently contains the below strings"
        threat_actor = "Lazarus Group"
        family = "BeaverTail & Ferret"
        variant = "N/A"
        target_entity = "file"
    
    strings:
        $1 = "import base64,platform,os,subprocess,sys\ntry:import requests\nexcept:subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])" //invisibleFerret MainDecoded
        $2 = "const fs_promises = require(\"fs/promises\")" //beaverTail DropperDecoded
        $3 = "if cmd == '':o=''" //invisibleFerret PayDecoded
        $4 = /pq\=\"tXt3rqfmL/ //Contagious Interview watermark frequently observed in BeaverTail/FERRET samples/

        // invisibleFerret variant numeric identifiers
        $type1s = /\n?sType ?\= ?[\'|\"][a-zA-Z0-9]{1,10}[\'|\"]/
        $type1g = /\n?gType ?\= ?[\'|\"][a-zA-Z0-9]{1,10}[\'|\"]/

        // invisibleFerret variant alphanumeric identifiers
        $type2s = /\n?sType ?\= ?[\'|\"]\w{1,10}\d/
        $type2pq = /\n?pq ?\= ?[\'|\"]tXt3rqfmL.*[\'|\"]/

        // deobfuscation commands
        $inline_deob1 = /\S{1,10} \=(\'|\")(\\n)?import base64(\\n)?\S{1,10} ?\= ?base64\.b[0-9]{2}decode ?\(\S{1,10}\[\d*\:\]\)(\\n)?\S{1,10}\=\S{1,10}\[(\d{1,10}|\:|\d){3}\]/

        //JSON Wrapped Samples
        $json1 = /\{\"[a-zA-Z]{2,12}":"\(function ?\(\_0x[a-zA-Z0-9]{6}\, ?\_0x[a-zA-Z0-9]{6}\) ?\{function \_0x[a-zA-Z0-9]{6}\(\_0x[a-zA-Z0-9]{6}/

        // invisibleFerret BowDecoded
        $tokenizedImport1 = "_m='-m'"
        $tokenizedImport2 = "_pp='pip'"
        $tokenizedImport3 = "_inl='install'"
    
    condition:
        vt.metadata.new_file and (
            any of ($1,$2,$3,$4) and (all of ($tokenizedImport*) or all of ($type1*) or all of ($type2*) or
            any of ($inline_deob*) or any of ($json*))
        )
}

rule Beavertail_Contacts_pdown { // checks for files that send a GET request for pdown
    meta:
        author = "Apodixis"
        date = "MAR2025"
        description = "pdown is a python wheel commonly downloaded by BeaverTail to install dependencies for [VARIANT]Ferret payloads. Searching for files that contact domains hosting pdown is a reliable way to identify BeaverTail samples"
        threat_actor = "Lazarus Group"
        family = "FERRET Malware"
        variant = "N/A"
        target_entity = "file"

        condition:
            for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
                vt_behaviour_processes_created matches /C\:\\\\Windows\\\\system32\\\\cmd\.exe \/d \/s \/c \\\"curl \-Lo \\\"C\:\\\\Users\\\\\<?[0-9a-zA-Z]+\>?\\\\AppData\\\\Local\\\\Temp\\\\p\.zi\\\" \\\"https?\:\/\/\d+\.\d+\.\d+\.\d+\:12[24]4\/pdown/
            ) and for any vt_behaviour_http_conversations in vt.behaviour.http_conversations: (
                vt_behaviour_http_conversations.url matches /https?:\/\/[1-9]\d{0,2}\.(\d{1,3}\.){2}\d{1,3}:(1\d{3}|[2-5]\d{3,4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\/p?down/
                and vt_behaviour_http_conversations.request_method == vt.Http.Method. GET
            )
}

rule File_Contacts_defy_domains { // Searches for C2 domains with the /devy/v# construction, whose HTTP responses often contain a BeaverTail downloader
    meta:
        author = "Apodixis"
        date = "18JUN2025"
        description = "Contagious Interview frequently reuses malicious domains to serve malware"
        threat_actor = "Lazarus Group"
        family = "N/A"
        variant = "N/A"
        target_entity = "file"

    condition:
        for any vt_behaviour_http_conversations in vt.behaviour.http_conversations: (
            vt.metadata.new_file and vt_behaviour_http_conversations.url matches /https?:\/\/(fashdefi\.shop|bujey\.store)\:\d{3,5}\/defy\/v\d+/i
        )
}

rule axiosGet_ArrayObfuscation { // Samples that download BeaverTail downloaders are frequently found on GitHub and other code hosting sites, these sites often use api.npoint.io
    meta:
        author = "Apodixis"
        date = "14OCT2025"
        description = "Contagious Interview Activity often includes the use of files that contain instructions to download the initial BeaverTail sample"
        threat_actor = "Lazarus Group"
        family = "N/A"
        variant = "N/A"
        target_entity = "file"

    strings:
    $byteArray = /const \w{1,15} ?\= ?new \w{1,15}\(\w{1,15}\)\;/
    $byteArrayObf = /const \w\{1,15} ?\= ?new TextDecoder\([\`\'\"]utf\-8[\`\'\"]\)\;/
    $axiosGet = /axios\.get\(\w{1,15}\.decode\(\w{1,15}\)\)/

    condition:
        vt.metadata.new_file and all of ($byteArray*) and $axiosGet
}

rule File_Obfuscation_Command_Concatenation { // Searches for commands commonly found in BeaverTail/FERRET specimens (with concatenation as an obfuscation method)
    meta:
        author = "Apodixis"
        date = "05SEP2025"
        description = "Contagious Interview samples identified using simple concatenation to deobfuscate commands at runtime; fs:~16JUL2025"
        threat_actor = "Lazarus Group"
        family = "BeaverTail / FERRET"
        variant = "N/A"
        target_entity = "file"

    strings:
        $method1 = /try\{const [a-zA-Z0-9]{1,10} ?\= ?[fF]unction\([\'\"return\+]{11,25}\+[\'\"]\\\\x20\([\'\"functio\+]{13,31}\+[\'\"]\(/ //try{const $\w=Function(return(function(
        $method2 = /[\'\"JSON\+]{9,15}\+[\'\"](\.p)[\'\"arse\+]{9,17}\+[\'\"]\(/ //JSON.parse(
        $method3 = /[\'\"Buffer\.concat\+]{18,51}\+[\'\"]\(\[?[\'\"cipher\.udat\+]{18,54}\(/ //Buffer.concat([cipher.update(
        $method4 = /(\\\\x20|[\'\"functio\+]){13,32}([\'\"\+]{2})[\'\"decryptPasswo\+]{20,59}\(/ //function decryptPassword(
        $method5 = /(\\x20|[\'\"socket\+]){12,25}\+[\'\"\.on\+]{7,13}\((\\\\x22|\\\\x20|[\'\"comand\+\,]){12,35}\(/ //socket.on('command',
        $method6 = /(\\\\x20|[ \'\"curentClipboad\+]){38,94}(\\\\x20|[ \'\"\=stdou\+]){12,25}/ //currentClipboardContent =stdout)
        $method7 = /[\'\"\.GlobaKeyrdListn\+]{37,88}/ //GlobalKeyboardListener
        $method8 = /[\'\"encryptd_k\+]{22,52}/ //encrypted_key
        $dep1 = /(\\\\x0a|\\\\x20|[\'\"const\+]){11,24}(\\\\x20|[\'\"axios\+]){11,24}\=(\\\\x20|[\'\"require\+]){13,29}\((\\\\x22|[\'\"axios\+]){11,24}/ //const axios=require(axios
        $dep2 = /(\\\\x0a|\\\\x20|[\'\"const\+]){11,24}(\\\\x20|[\'\"sqlite3\+]){11,24}\=(\\\\x20|[\'\"require\+]){13,29}\((\\\\x22|[\'\"sqlite3\+]){11,24}/ //const sqlite3=require(sqlite3
        $dep3 = /try\{const os\=require\([\'\"]os[\'\"]\)\,fs\=require\([\'\"]fs[\'\"]\)\,\{execSync\,spawn\}\=require\([\'\"child_process\+]{22,52}/ //try{const os=require('os'),fs=require('fs'),{execSync,spawn}=require(child_process)

    condition:
        vt.metadata.new_file and 7 of ($method*) and 2 of ($dep*)
}