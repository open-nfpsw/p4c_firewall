Testing the P4/C Firewall:

1.  Install the Firewall rpm package for your specific SmartNIC.
      http://iconicsp4.cloudapp.net/repo/p4c-firewall/

2.  Run the Firewall Controller on the host where the SmartNIC is installed:
      python fw_v2_ctrlr.py -h
      python fw_v2_ctrlr.py -i 111.111.111.111 -t 100

3.  Run the Test Script where you generate your traffic:
      ./p4c-firewall-test.sh <internal port> <external port>
      ./p4c-firewall-test.sh p6p1 p6p2

4.  Setup:
   ______________           ______________
  |   SmartNIC   |         |   DumbNIC    |
  |            p0|---------|p6p1<Internal>|
  |   Firewall   |         |              |
  |            p4|---------|p6p2<External>|
  |______________|         |______________|

  The test script will do the following:
    - Send a packet from <external> to p4: No rule yet -> Drop
    - Send a packet from <internal> to p0: New Flow -> NAT -> Forward to p4
    - Send a packet from <external> to p4: Known Flow -> NAT -> Forward to p0
