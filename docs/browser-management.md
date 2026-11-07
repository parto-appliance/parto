# Configure Hub and Spoke in the browser · Parto 0.13.0

Complete the [console setup](setup.md) on both appliances first. The screenshots
below show the Parto 0.13.0 web interface rendered with example addresses,
identities and traffic. Replace these values with your own.

## 1. Sign in to the Hub

Open the Hub's **HTTPS management · WAN only** URL from its console, for example
`https://10.70.10.10:8443`. Use a computer that can reach that WAN from a
trusted network. The Hub lists eth0 and, in dual-WAN mode, eth2. The Spoke lists
eth0. Use the locally displayed certificate SHA-256 fingerprint to verify the
appliance's self-signed certificate before trusting it. Sign in as **admin**
with the root password you set on this appliance's console.

![Browser sign-in with admin and an empty password field](images/013/web-login.png)

## 2. Hub · Create your Hub

Enter a **Node name**, select **Transport**, and enter the **Reachable Hub IPv4**
that the Spoke can reach. Enable **Share Internet with spokes** if you want
Internet egress through this Hub. Leave **Isolate spokes from each other**
selected unless their LANs should communicate. Select **Create Hub**.
See the [three protocol options](../README.md#protocol-options).

![Hub site form with TLS transport, reachable IPv4 and sharing settings](images/013/hub-create.png)

## 3. Hub · Download the invitation

Choose **Download invitation**. With **Encrypt this file with a passphrase**
selected, enter and confirm an exchange passphrase of 16–256 characters. Send
the resulting `<hub>-invitation.json` to the intended Spoke operator. Send the
passphrase separately. The Hub now waits for a Spoke request.

![Hub invitation export with the encryption option](images/013/hub-invitation.png)

## 4. Spoke · Sign in and import the invitation

Open this Spoke's own console URL on eth0 and sign in as **admin** with this
Spoke's root password. In **Import your Hub invitation**, choose the invitation
JSON from your computer.

![Spoke invitation upload screen](images/013/spoke-invitation.png)

If encrypted, enter the file's exchange passphrase and choose **Unlock file**.
Use this same unlock dialog for an encrypted request or approval later.

![Passphrase prompt for an encrypted exchange file](images/013/unlock-exchange.png)

Compare the Hub's name and fingerprint with its operator over a trusted
channel. Check the trust box, then choose **Trust this Hub and continue**.

![Spoke reviewing a Hub identity before trusting the invitation](images/013/spoke-trust.png)

## 5. Spoke · Create the site

Enter a unique **Node name**, then choose **Create Spoke**. The transport is
taken from the trusted Hub invitation.

![Spoke site name with transport inherited from the invitation](images/013/spoke-create.png)

## 6. Spoke · Download the request

Choose **Download request** and send `<spoke>-request.json` back to the Hub
operator. If you encrypt it, share its exchange passphrase separately. The
Spoke now waits for the Hub approval.

![Spoke request download screen](images/013/spoke-request.png)

## 7. Hub · Import and approve the request

On the Hub's **Waiting for a Spoke request** screen, choose the request JSON.
Unlock it if needed, verify the Spoke identity with its operator, check the
trust box and select **Approve this Spoke**.

![Hub reviewing a Spoke identity before approval](images/013/hub-approve.png)

## 8. Hub · Download the matching approval

Confirm the intended Spoke under **File to download** and choose **Download
approval**. Return `<spoke>-approved.json` only to that Spoke. Every Spoke gets
its own approval file. The Hub can now activate.

![Hub approval download shows the named Spoke as recipient](images/013/hub-approval.png)

## 9. Spoke · Import the approval

On the matching Spoke, choose the approval JSON. Unlock it if needed, confirm
it came from the trusted Hub, check the trust box and select **Import approval**.

![Spoke importing the Hub approval for this recipient](images/013/spoke-approval.png)

## 10. Activate both appliances

Select **Activate and open Monitor** on the Hub, then on the Spoke. Give the
tunnel and BGP time to establish. Both sides should show the intended peer.

![Hub ready to activate](images/013/hub-activate.png)

![Spoke ready to activate](images/013/spoke-activate.png)

## 11. Check the connection and test a client

In **Monitor → Trusted connections**, look for **Tunnel established** and
**BGP Established**. The Hub can compare its total and individual Spoke rates.
The Spoke shows its link to the Hub. **Topology** shows all approved sites on
the Hub and the local Spoke plus its Hub on a Spoke.

![Hub Monitor showing the approved Spoke and one-hour overlay traffic](images/013/hub-monitor.png)

![Spoke Monitor showing the connection to its Hub](images/013/spoke-monitor.png)

From a Spoke client, test the Spoke LAN gateway, the Hub LAN if configured,
and Internet and DNS if sharing is enabled. For example, with the guide's LAN
addresses on a Linux client:

```sh
ping -c 3 172.30.212.254
ping -c 3 172.30.211.254
ping -c 3 1.1.1.1
getent hosts example.com
```

With dual WAN, check that the public egress address belongs to the second WAN
and that shared Internet stops if that uplink is unavailable. Use **Monitor
→ Connect another Spoke** on the Hub to repeat the same file exchange for
another site while existing peers remain active.

Traffic history covers up to one hour while the management service is running.
It starts fresh after a reboot or service restart. Keep port 8443 on trusted
administration paths. Forward only the chosen transport for public peers.
