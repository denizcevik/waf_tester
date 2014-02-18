Web Application Firewall Test Script

Usage: waf_tester.py options

Options:

  -u --url: A Single URL behind WAF/IPS
  -t --type: WAF Behavior (Block/Reset/Response)
  -w --time-out: timeout value to indetify droped connection
  -s --string: string value can be found in WAF error code
  -k --sleep: Wait time before request (default 0 second)
  -o --output: Print related [Blocked|Bypassed|All] (default All) 

Examples:

  python waf_tester.py -u http://www.sitebehindwaf.com/index.asp -t Response --string "302 Redirect" --output All
  python waf_tester.py -u http://www.sitebehinips.com/index.asp -t Block --time-out 10 --output Bypassed
  python waf_tester.py -u http://www.sitebehindfw.com/index.asp -t Reset --output Blocked
  python waf_tester.py -u http://www.sitebehindfw.com:8080/index.asp -t Reset