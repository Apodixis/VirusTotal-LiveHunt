rule GitHubUrlExecution { //Matches for files containing previously identified methods of encoded URLs which are then queried to receive a payload that is dynamically executed 
    meta:
        source1 = "https://github.com/njkr/goldencity/blob/main/server/controllers/userController.js"
        source2 = "https://github.com/wgueds/goldencity/blob/main/contracts/config/.config.env"
        source2 = "https://github.com/wgueds/goldencity/blob/main/contracts/controllers/userController.js"
        source3 = "https://github.com/abhisheksingh98/GoldenCity/blob/main/server/controllers/userController.js"
        author = "Apodixis"
        date = "22OCT2025"
        description = "Searches for strings used to execute code returned by an HTTP GET request"
        target_entity = "File"

    strings:
        $execution1 = /eval\(\w{1,20}\.data/ //catches unsafe 'eval' commands, which can execute code
        $execution2 = /\(Function\.constructor\)\([\`\'\"]require[\`\'\"]\,/ //catches invokation of the 'Function' constructor, which can execute code passed into it
        $execution3 = /Function\([\`\'\"]require[\`\'\"]\, ?\w{1,20}\.data/ //catches invokation of the 'Function' constructor, which can execute code passed into it

        $request1 = /await axios\.get\(/ //catches the use of 'axios.get' to send HTTP GET requests (Sources 1-3)
        $request2 = /(await )?fetch\(/ //JavaScript-native HTTP client (and Node.js node-fetch import of the Fetch HTTP client)
        $request3 = /await ky\.get\(/ //HTTP client built on top of Fetch
        $request4 = /await got\(/ //HTTP library for Node.js
        $request5 = /await superagent\.get\(/ //SuperAgent HTTP client 
        $request6 = /ajax\(\{[\r\n]{1,2} {1,4}url\: [\`\'\"]http.{20,50}[\`\'\"]\,[\r\n]{1,2} {1,4}method\: [\`\'\"]GET[\`\'\"]\,/ //ajax fetch method
        $request7 = /new XMLHttpRequest\(/ //XMLHttpRequest

        $content1 = /\w{1,20}\=[\`\'\"]([a-zA-Z0-9\+\/\=]{1,256}|[a-zA-Z0-9\=\-\_]{1,256})[\`\'\"]/ //catches variables containing base64-encoded values (Source2)
        $content2 = /atob\(process\.env\..{1,20}\)\;/ //catches the use of 'atob' to base64 decode values stored in a .env file (Source2)
        $content3 = /api\.npoint\.io\// //api.npoint.io is an JSON storage and schema validation tool that DPRK cyber actors frequently exploit to deliver malware samples (Sources1-3)
        $content4 = /const \w{1,20} ?\= ?\[(\d{2,3}\, ?|[\r\n]{1,2} {1,4})*\d{2,3}[\r\n]{1,2} {1,4}\]\;/ //Catches decimal-encoded byte arrays, which DPRK MCAs have previously hidden URLs in (Source3)

    condition:
        vt.metadata.new_file and any of ($execution*) and any of ($request*) and any of($content*)
}
