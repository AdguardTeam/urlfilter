# AdGuard urlfilter proxy

This is a MITM proxy that is able to apply AdGuard content blocking rules to the web pages.

Here's what you'll need to build and run the proxy:

* go v1.13 or newer
* openssl (or any other tool to generate the root CA)

> **Limitations**
> Please note, that at the time of writing, the library is limited to a subset of AdGuard content blocking rules.
Check out the TODO list in the main README to find out what exactly is missing. 

## How to build

```bash
git clone https://github.com/AdguardTeam/urlfilter
cd urlfilter/cmd
go build -o adguard
```

## How to prepare

### 1. Generate self-signed root CA

First of all, you need to generate a root certificate that will be used by the proxy.

Use the following openssl commands to do this:

```bash
openssl genrsa -out root.key 2048
openssl req -new -x509 -key demo.key -out root.crt
```

### 2. Install the certificate as a trusted authority

#### Windows

1. On the Windows computer, start MMC (mmc.exe).
2. Add the Certificates snap-in for the computer account and manage certificates for the local computer.
2. Import the root CA certificate into Trusted Root Certification Authorities > Certificates.

#### Mac

1. Double-click the `root.crt` CA certificate to open it in Keychain Access. 
    * The root CA certificate appears in login.
2. (Optional) Copy the root CA certificate to System. 
    * This step is necessary only if you want all users to trust the certificate.
3. Open the root CA certificate, expand "Trust", select "Use System Defaults", and save your changes.
4. Reopen the root CA certificate, expand "Trust", select "Always Trust", and save your changes.
5. (Optional, only if you did step 2) Delete the root CA certificate from login.

### 3. Prepare filter lists

Please note, that at the current moment, AdGuard urlfilter supports a limited subset of the filtering rules syntax.
Commands below download the versions of AdGuard filter lists that are compatible with AdGuard urlfilter.

These commands download AdGuard Base filter, Tracking Protection filter, and Social widgets filter.
```bash
curl http://filters.adtidy.org/extension/android-content-blocker/filters/2.txt > adguard_base.txt
curl http://filters.adtidy.org/extension/android-content-blocker/filters/3.txt > adguard_tracking_protection.txt
curl http://filters.adtidy.org/extension/android-content-blocker/filters/4.txt > adguard_social.txt
```

### 4. Run AdGuard urlfilter proxy

```bash
./adguard -l 0.0.0.0 -p 8080\
          -c root.crt\
          -k root.key\
          -f adguard_base.txt\
          -f adguard_tracking_protection.txt\
          -f adguard_social.txt
```

### 5. Configure your browser to use this proxy

You can use your browser settings to do this.

Alternatively, you can use a browser extension like [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega) 
that allows you to quickly enable or disable proxy, or even configure an HTTPS proxy (read below how to run AdGuard urlfilter proxy in this mode).

## Securing the proxy

If you're running this proxy on a public server, most likely you'd like to secure it.

There are two things you can do:

* Proxy authentication.
    Configure username and password to make sure there can be no unauthorized use of the proxy.
* HTTPS proxy.
    You can run the proxy as an HTTPS (HTTP over TLS) proxy to make sure 
    that your connection to it stays secure, and no one can see what's inside.
    In this case, the proxy will use your custom root certificate to 
    generate a new HTTPS certificate, that will be used to encrypt the traffic.
    
**Example:**

```bash
./adguard -l 0.0.0.0 -p 8080\
          -c root.crt\
          -k root.key\
          -f adguard_base.txt\
          -f adguard_tracking_protection.txt\
          -f adguard_social.txt\
          -u user\
          -a password\
          -t -n yourdomainname
```

## Command-line arguments

```bash
$ ./adguard -h
Usage:
  adguard [OPTIONS]

Application Options:
  -v, --verbose     Verbose output (optional).
  -o, --output=     Path to the log file. If not set, it writes to stderr.
  -l, --listen=     Listen address. (default: 0.0.0.0)
  -p, --port=       Listen port. Zero value disables TCP and UDP listeners.
                    (default: 8080)
  -c, --ca-cert=    Path to a file with the root certificate.
  -k, --ca-key=     Path to a file with the CA private key.
  -f, --filter=     Path to the filter list. Can be specified multiple times.
  -u, --username=   Proxy auth username. If specified, proxy authorization is
                    required.
  -a, --password=   Proxy auth password. If specified, proxy authorization is
                    required.
  -t, --https       Run an HTTPS proxy (otherwise, it runs plain HTTP proxy).
  -n, --https-name= Server name for the HTTPS proxy.

Help Options:
  -h, --help        Show this help message
```