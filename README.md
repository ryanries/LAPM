# Local Admin Password Maintainer
------------------------

(June 18, 2015: Microsoft's LAPS (Local Admin Password Solution) is getting a lot of attention lately, so I figured I'd open source my version, that I released via my blog three months earlier.)

Active Directory is great for robust, centralized management of a large amount of I.T. assets.  But even once you have Active Directory, you're still left with that problem of what to do with local administrator accounts on all of the domain members.  You probably don't want to disable the local admin account, because you'll need it in case the computer is ever in a situation where it can't contact a domain controller.  But you don't have a good way of updating and maintaining the local Administrator password across your entire environment, either.  Everyone knows better than to use Group Policy Preferences to update the local administrator password on domain members, as it is completely unsecure.  Most other solutions involve sending the administrator passwords across the network in clear-text, require an admin to manually run some scripts or software every time that may not work well in complicated networks, and they still leave you with the same local administrator password on every machine... so if an attacker knocks over any one computer in your entire domain, he or she now has access to everything.

This is the situation Local Admin Password Maintainer seeks to alleviate.  LAPM easily integrates into your Active Directory domain and fully automates the creation of random local administrator passwords on every domain member.  The updated password is then transmitted securely to a domain controller and stored in Active Directory.  Only users who have been given the appropriate permissions (Domain Administrators and Account Operators, by default) may view any password.

The solution is comprised of two files: Install.ps1, which is the one-time install script, and LAPM.exe, an agent that will periodically (e.g., once a month,) execute on all domain members.  Please note that these two files will always be digitally signed by me.

For more details and instructions, see:

https://myotherpcisacloud.com/post/local-admin-password-maintainer